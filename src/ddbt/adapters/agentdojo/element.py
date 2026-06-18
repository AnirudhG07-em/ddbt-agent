"""AgentDojo defense element (v4) — ddbt as a judge-gated tool executor.

Subclasses AgentDojo's ToolsExecutor and runs every proposed tool call through the ddbt
engine (whose decider is the LLM step-judge). A DENY isn't executed — it becomes a tool
error the agent sees; ALLOW/ASK proceed (no human in a benchmark; ASK is logged). The
engine's goal is seeded from the user task; tool outputs are quarantined so the judge can
spot injected/stray steps. No keyword classifier — the judge decides.
"""

from __future__ import annotations

import tempfile
from ast import literal_eval

from agentdojo.agent_pipeline.tool_execution import EMPTY_FUNCTION_NAME, ToolsExecutor, is_string_list
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.types import text_content_block_from_string

from ddbt.core.engine import Effect, Engine


class DdbtToolsExecutor(ToolsExecutor):
    def __init__(self, tool_output_formatter=None, step_judge=None, block_states=(Effect.DENY,)):
        super().__init__() if tool_output_formatter is None else super().__init__(tool_output_formatter)
        self.step_judge = step_judge  # None → engine default (AnthropicStepJudge, needs key)
        self.block_states = set(block_states)
        self._base = tempfile.mkdtemp(prefix="ddbt-agentdojo-")
        self._counter = 0
        self.stats = {"allowed": 0, "blocked": 0, "blocked_calls": []}

    def _engine_for(self, query: str) -> Engine:
        self._counter += 1
        eng = Engine(f"adojo-{self._counter}", workspace_root=self._base, base_dir=self._base, step_judge=self.step_judge)
        eng.on_session_start("startup", self._base)
        eng.on_user_prompt(query)  # the user task is the trusted goal the judge checks against
        return eng

    def query(self, query, runtime: FunctionsRuntime, env=None, messages=(), extra_args=None):
        from agentdojo.functions_runtime import EmptyEnv

        env = env if env is not None else EmptyEnv()
        extra_args = extra_args if extra_args is not None else {}
        messages = list(messages)
        if not messages or messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        tool_calls = messages[-1].get("tool_calls")
        if not tool_calls:
            return query, runtime, env, messages, extra_args

        eng = self._engine_for(query)
        try:
            results = []
            for tc in tool_calls:
                if tc.function == EMPTY_FUNCTION_NAME:
                    results.append(self._err(tc, "Empty function name."))
                    continue
                if tc.function not in (t.name for t in runtime.functions.values()):
                    results.append(self._err(tc, f"Invalid tool {tc.function}."))
                    continue
                decision = eng.evaluate_action(tc.function, dict(tc.args))
                if decision.effect in self.block_states:
                    self.stats["blocked"] += 1
                    self.stats["blocked_calls"].append((tc.function, decision.reason))
                    results.append(self._err(tc, f"[ddbt blocked: {decision.state}] {decision.reason}"))
                    continue
                for k, v in tc.args.items():
                    if isinstance(v, str) and is_string_list(v):
                        tc.args[k] = literal_eval(v)
                output, error = runtime.run_function(env, tc.function, tc.args)
                self.stats["allowed"] += 1
                eng.record_result(tc.function, dict(tc.args), {"output": str(output)})  # quarantine
                results.append(self._mk(tc, self.output_formatter(output), error))
        finally:
            eng.close()
        return query, runtime, env, [*messages, *results], extra_args

    def _mk(self, tc, content_str, error):
        from agentdojo.types import ChatToolResultMessage

        return ChatToolResultMessage(
            role="tool", content=[text_content_block_from_string(content_str)],
            tool_call_id=tc.id, tool_call=tc, error=error,
        )

    def _err(self, tc, msg):
        return self._mk(tc, "", msg)
