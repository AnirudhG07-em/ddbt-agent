"""AgentDojo defense element — ddbt as a tool-call gate (doc §5, §7).

`DdbtToolsExecutor` subclasses AgentDojo's `ToolsExecutor` and consults the ddbt
engine before running each proposed tool call. A DENY (out-of-envelope sink, sensitive
source) is not executed — it becomes a `ChatToolResultMessage` with an `error`, exactly
how a real refusal looks to the agent, so AgentDojo's attack checker sees the sink never
fired. ALLOW/ASK proceed (no human in a benchmark; ASK is logged, not blocked — our
attacks surface as DENY, not ASK).

The envelope is seeded from the (trusted) user task: destination identifiers named in
the task are granted; an attacker recipient injected via tool output is, by
construction, not in the envelope → DENY. The injection's prose never reaches the judge.
"""

from __future__ import annotations

import tempfile
from ast import literal_eval

from agentdojo.agent_pipeline.tool_execution import EMPTY_FUNCTION_NAME, ToolsExecutor, is_string_list
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.types import text_content_block_from_string

from ddbt.adapters.agentdojo.classifier import classify_agentdojo, extract_identifiers
from ddbt.core.engine import Effect, Engine
from ddbt.policy.defaults import Policy, default_policy


class DdbtToolsExecutor(ToolsExecutor):
    """A ToolsExecutor that enforces the ddbt envelope on every tool call."""

    def __init__(self, tool_output_formatter=None, policy: Policy | None = None, block_states=(Effect.DENY,)):
        if tool_output_formatter is None:
            super().__init__()
        else:
            super().__init__(tool_output_formatter)
        self.policy = policy or default_policy()
        self.block_states = set(block_states)
        self._base = tempfile.mkdtemp(prefix="ddbt-agentdojo-")
        self._counter = 0
        # per-task stats, readable by the harness after each run
        self.stats = {"allowed": 0, "blocked": 0, "blocked_calls": []}

    def _engine_for(self, query: str) -> Engine:
        self._counter += 1
        eng = Engine(
            f"adojo-{self._counter}",
            workspace_root=self._base,
            policy=self.policy,
            base_dir=self._base,
            classifier=classify_agentdojo,
        )
        eng.on_session_start("startup", self._base)
        # seed the envelope from destination identifiers named in the trusted task
        for ident in extract_identifiers(query):
            eng.envelope.grant_domain(ident)
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
            for tool_call in tool_calls:
                if tool_call.function == EMPTY_FUNCTION_NAME:
                    results.append(self._error_result(tool_call, "Empty function name provided."))
                    continue
                if tool_call.function not in (t.name for t in runtime.functions.values()):
                    results.append(self._error_result(tool_call, f"Invalid tool {tool_call.function}."))
                    continue

                decision = eng.evaluate_action(tool_call.function, dict(tool_call.args))
                if decision.effect in self.block_states:
                    self.stats["blocked"] += 1
                    self.stats["blocked_calls"].append((tool_call.function, decision.reason))
                    results.append(
                        self._error_result(
                            tool_call, f"[ddbt blocked: {decision.checkpoint}] {decision.reason}"
                        )
                    )
                    continue

                # allowed → execute exactly as the stock executor would
                for k, v in tool_call.args.items():
                    if isinstance(v, str) and is_string_list(v):
                        tool_call.args[k] = literal_eval(v)
                output, error = runtime.run_function(env, tool_call.function, tool_call.args)
                self.stats["allowed"] += 1
                eng.record_result(tool_call.function, dict(tool_call.args), {"output": str(output)})
                results.append(
                    self._make_result(tool_call, self.output_formatter(output), error)
                )
        finally:
            eng.close()
        return query, runtime, env, [*messages, *results], extra_args

    def _make_result(self, tool_call, content_str, error):
        from agentdojo.types import ChatToolResultMessage

        return ChatToolResultMessage(
            role="tool",
            content=[text_content_block_from_string(content_str)],
            tool_call_id=tool_call.id,
            tool_call=tool_call,
            error=error,
        )

    def _error_result(self, tool_call, message):
        return self._make_result(tool_call, "", message)
