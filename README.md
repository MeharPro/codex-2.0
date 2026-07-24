# Codex 2.0 — laptop-hosted MCP gateway

Codex 2.0 turns a Mac into a powerful MCP host that approved AI clients can
reach through an OpenAI Secure MCP Tunnel. It exposes terminal, filesystem,
Playwright browser automation, macOS screenshots and Accessibility controls,
installed Codex skill discovery, and a local activity journal.

> [!CAUTION]
> This is intentionally equivalent to remote code execution as your macOS
> user. Read [SECURITY.md](SECURITY.md), keep credentials out of the repository,
> and only connect clients and users you trust.

## What it provides

- One-shot and persistent interactive terminal tools.
- Filesystem access, configured by default from `/`.
- A dedicated Playwright/CDP browser session.
- macOS screenshots, application activation, Accessibility inspection, mouse,
  and keyboard controls.
- Discovery and reading of locally installed Codex skills and plugin metadata.
- Workspace-bound tool activity journals under
  `~/.codex/gateway_sessions`.
- A safety-oriented MCP instruction policy from `OPERATING_POLICY.md`.

Codex's signed Computer Use process, trusted Chrome-extension runtime, hidden
system prompt, and OpenAI-hosted connector OAuth sessions cannot be copied into
an independent MCP server. This project provides direct local equivalents where
possible; clients must connect services such as Google Drive or GitHub
separately.

## Requirements

- macOS with Python 3.11 or newer.
- `zsh`, Node.js, and npm.
- OpenAI Secure MCP Tunnel access, including:
  - the `tunnel-client` executable;
  - a tunnel ID created for your workspace;
  - its runtime API key.
- A ChatGPT plan/workspace that supports custom MCP apps, or another MCP client
  compatible with the tunnel.
- Optional desktop controls:
  - `brew install cliclick`
  - macOS Screen Recording and Accessibility permission for the launching
    terminal or tunnel process.

OpenAI distributes tunnel access and credentials through the supported ChatGPT
developer-mode workflow. If your workspace does not show Secure MCP Tunnel or
custom MCP app setup, ask its administrator or OpenAI support; this repository
does not create or bypass access.

## Step-by-step setup

### 1. Clone and create the Python environment

```bash
git clone https://github.com/MEHARPro/codex-2.0.git
cd codex-2.0
python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/pip install -r requirements.txt
./.venv/bin/playwright install chromium
```

### 2. Install the OpenAI tunnel client

Follow the Secure MCP Tunnel instructions presented by OpenAI for your ChatGPT
workspace. Confirm the installed client is available:

```bash
tunnel-client --version
```

If it is installed outside `PATH`, set its absolute location as
`TUNNEL_CLIENT` in `.env`.

### 3. Store the runtime key outside the repository

```bash
mkdir -p "$HOME/.config/codex-mcp"
chmod 700 "$HOME/.config/codex-mcp"
printf '%s' 'PASTE_YOUR_RUNTIME_API_KEY_HERE' \
  > "$HOME/.config/codex-mcp/runtime-api-key"
chmod 600 "$HOME/.config/codex-mcp/runtime-api-key"
```

Avoid entering the real value in commands that are recorded in shared shell
history. A secure editor or hidden-input credential workflow is preferable.

### 4. Configure the local, ignored environment file

```bash
cp .env.example .env
chmod 600 .env
```

Edit `.env` and replace `tunnel_REPLACE_ME` with your own tunnel ID. Keep
`.env` local—it is ignored by Git.

### 5. Install the one-line command

```bash
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/bin/codex-mcp" "$HOME/.local/bin/codex-mcp"
```

Add `~/.local/bin` to your shell `PATH` if needed:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### 6. Start the gateway in a project folder

```bash
cd /path/to/project
codex-mcp
```

Or pass the folder directly:

```bash
codex-mcp /path/to/project
```

The selected folder becomes the default terminal working directory. Switching
to another folder restarts the managed runtime so the new workspace is applied.

Useful lifecycle commands:

```bash
codex-mcp status
codex-mcp restart /path/to/project
codex-mcp stop
```

### 7. Connect ChatGPT

The exact labels vary by plan and rollout, but the workflow is:

1. Enable developer mode for your ChatGPT workspace/account.
2. Open **Settings** or **Workspace Settings → Apps**.
3. Create a custom MCP app.
4. Select the OpenAI Secure MCP Tunnel created for this server.
5. Scan the MCP tools.
6. Review every action, especially terminal, filesystem, keyboard, mouse, and
   write operations.
7. Create or publish the app and explicitly connect it for your user.
8. Start a new chat, select the app, and ask it to call `gateway_info` followed
   by `terminal_status`.

ChatGPT freezes an approved snapshot of tool definitions. After updating this
server, refresh its actions in Enterprise/Edu. A published Business custom app
may need to be recreated and republished to adopt changed tools.

### 8. Connect another MCP client

Use the tunnel endpoint and authentication details provided by OpenAI in the
client's remote-MCP configuration. For a local stdio smoke test, point the
client directly at:

```text
/absolute/path/to/codex-2.0/.venv/bin/python
/absolute/path/to/codex-2.0/gateway.py
```

The first line is the command and the second is its argument. Set
`CODEX_MCP_WORKSPACE=/path/to/project` when launching locally if you want a
specific default folder.

## Browser and desktop setup

The browser tools use Chrome DevTools Protocol at
`http://127.0.0.1:9222` by default. Launch a dedicated Chrome profile:

```bash
open -na "Google Chrome" --args \
  --remote-debugging-port=9222 \
  --user-data-dir="$HOME/.codex-gateway/chrome-profile"
```

Override the endpoint with `CDP_URL` if needed.

For desktop tools, grant Screen Recording and Accessibility permission in
**System Settings → Privacy & Security** to the terminal or process launching
`tunnel-client`.

## Local verification

Check syntax without exposing credentials:

```bash
./.venv/bin/python -m py_compile gateway.py host_bridge/ctf_browser_mcp.py
zsh -n bin/codex-mcp
```

Start the stdio MCP server locally:

```bash
CODEX_MCP_WORKSPACE="$PWD" ./.venv/bin/python gateway.py
```

It will wait for MCP messages on standard input. Press `Control-C` to stop it.

## Session history

Each gateway process records tool starts, finishes, failures, duration, and
redacted arguments under:

```text
~/.codex/gateway_sessions/YYYY/MM/DD/<session-id>.jsonl
```

The MCP does not receive the complete ChatGPT transcript, so these files contain
tool activity and explicit `gateway_session_note` entries—not native Codex
sidebar history.

## Updating

```bash
codex-mcp stop
git pull --ff-only
./.venv/bin/pip install -r requirements.txt
codex-mcp /path/to/project
```

Refresh or republish the ChatGPT app if the tool schema changed.

## Security reminder

Anyone who can invoke this MCP can potentially read or change files and execute
commands as your macOS user. Keep the runtime key private, constrain app access,
review action permissions, and stop the gateway when it is not needed.
