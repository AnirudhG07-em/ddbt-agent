# Giving the agent its own identity — credentials for `ddbt.json`

> **Status.** The **ticket** (floor) runs today — that's `.ddbt/grant.json`, enforced before every
> call. The **provider credentials** (ceiling) described here are the *next build*: `ddbt.json`'s
> `oauth` block is scaffolding, and nothing in ddbt consumes it yet. This doc is how you'll fill it
> once minting lands — and it doubles as the spec for that build. Don't treat the ceiling as live.

The idea (see the README's *"acts on your behalf, not on your account"*): the agent is a **separate
principal**. It gets its *own* scoped token per service, so even if ddbt is bypassed the token
*literally cannot* reach the rest of your account. Two layers, defence in depth:

- **Ceiling (provider-side):** a real token the provider issues, scoped as tightly as the provider
  allows. This is the hard limit — the agent can't exceed it no matter what.
- **Floor (ddbt ticket):** one uniform, task-shaped policy the providers can't express — "email
  only `acme.com`, at most 3 sends, expires in 1h" — checked *before* the call, on provenance. This
  is the only layer that catches an **injection-chosen** destination. Author it in `.ddbt/grant.json`.

Fill the floor first (it works now). The ceiling is below.

---

## Rule zero: never inline a secret

`ddbt.json` is meant to be committable. So it holds **references**, not secrets:

- a **client secret / API token** → the *name* of an env var that holds it (`..._env` fields)
- a **private key** → a **path** to a gitignored file (e.g. `.ddbt/github-app.pem`)

Put the real values in your shell, your `.env` (already gitignored and auto-loaded), or a secrets
manager. Add `.ddbt/*.pem` and `.env` to `.gitignore`.

---

## GitHub — a GitHub App with a short-lived install token

A GitHub **App** (not a personal token, not a classic OAuth app) is the least-privilege path: you
install it on **selected repositories** with a minimal permission set, and it mints a **1-hour
installation token** on demand.

1. **Create the app.** GitHub → Settings → Developer settings → **GitHub Apps** → *New GitHub App*.
   Give it a name; you can leave the callback URL blank for a token-only app.
2. **Scope the permissions** to the least the task needs, e.g. *Repository permissions →
   Contents: Read & write*, *Pull requests: Read & write*. Leave everything else *No access*.
3. **Generate a private key** (bottom of the app page) → downloads a `.pem`. Save it as
   `.ddbt/github-app.pem` (gitignored).
4. **Install the app** on *only the repositories* the agent may touch (Install App → choose repos).
5. Note the **App ID** (app settings page) and the **Installation ID** (the number in the URL after
   you install: `.../installations/<id>`).

```jsonc
"github": {
  "app_id": "123456",
  "installation_id": "78901234",
  "private_key_path": ".ddbt/github-app.pem",
  "repositories": ["acme/website"]      // the token is minted scoped to these
}
```

The install token expires in 1h and only covers the selected repos + granted permissions — that's
the ceiling.

---

## Gmail — OAuth with the `gmail.send` scope only

The agent should be able to **send** mail as a service identity, and **not** read your inbox. Gmail
supports that: request *only* `https://www.googleapis.com/auth/gmail.send`.

1. **Google Cloud Console** → create (or pick) a project → **APIs & Services** → enable the **Gmail
   API**.
2. **OAuth consent screen** → configure; add *only* the `gmail.send` scope.
3. **Credentials → Create credentials → OAuth client ID** → *Desktop app*. This gives you a
   **client ID** and **client secret**.
4. **Get a refresh token** for the sending account, authorizing *only* `gmail.send` (the OAuth
   Playground with "use your own credentials" works, or a one-off local script). Store all three as
   env vars — never in the file.

```bash
export DDBT_GMAIL_CLIENT_ID="....apps.googleusercontent.com"
export DDBT_GMAIL_CLIENT_SECRET="...."
export DDBT_GMAIL_REFRESH_TOKEN="1//...."
```

```jsonc
"gmail": {
  "client_id_env": "DDBT_GMAIL_CLIENT_ID",
  "client_secret_env": "DDBT_GMAIL_CLIENT_SECRET",
  "refresh_token_env": "DDBT_GMAIL_REFRESH_TOKEN",
  "scopes": ["https://www.googleapis.com/auth/gmail.send"]
}
```

Because the grant is `gmail.send`-only, a leaked token can send — never read, delete, or browse.
The ddbt ticket then narrows *sending* further (recipient domain, per-session quota).

---

## Jira — a bot user in one project role

Don't give the agent your Jira account. Create a **service (bot) user**, add it to **one project**
with a single role, and issue it an **API token**.

1. **Create a bot user** in your Atlassian org (a dedicated account, e.g. `ddbt-bot@acme.com`).
2. **Add it to exactly one project** with the least role that does the job (e.g. *Board admin* only
   if needed, else a plain *Member*).
3. **API token:** as that bot user, id.atlassian.com → *Security → API tokens → Create*. Store it
   in an env var.

```bash
export DDBT_JIRA_API_TOKEN="...."
```

```jsonc
"jira": {
  "base_url": "https://acme.atlassian.net",
  "bot_email": "ddbt-bot@acme.com",
  "api_token_env": "DDBT_JIRA_API_TOKEN",
  "project_key": "WEB"        // the bot only has rights in this project
}
```

---

## The whole picture

| | ceiling (provider) | floor (ddbt ticket) |
|---|---|---|
| **GitHub** | App on selected repos, 1h token, `contents:write` | reach only `github.com`, N pushes, TTL |
| **Gmail** | OAuth `gmail.send` only | recipient domain allow-list, N sends, TTL |
| **Jira** | bot user, one project role | one project, N transitions, TTL |

A leak in either layer is caught by the other. Today the floor is real (`.ddbt/grant.json`); the
ceiling above is the spec for what mints these tokens next — build it, then measure it before you
call it done.
