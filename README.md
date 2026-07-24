# Codex 2.0 — laptop-hosted MCP gateway

Codex 2.0 turns a Mac into a powerful MCP host that approved AI clients can
reach through an OpenAI Secure MCP Tunnel. It exposes terminal, filesystem,
Playwright browser automation, macOS screenshots and Accessibility controls,
installed Codex skill discovery, and a local activity journal.

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
  - a provider-generated tunnel ID;
  - your own OpenAI Platform runtime API key.
- A ChatGPT plan/workspace that supports custom MCP apps, or another MCP client
  compatible with the tunnel.
- Optional desktop controls:
  - `brew install cliclick`
  - macOS Screen Recording and Accessibility permission for the launching
    terminal or tunnel process.

Secure MCP Tunnel is documented for enterprise customers. Creating and managing
a tunnel requires the appropriate OpenAI Platform organization permissions, and
ChatGPT developer mode is a separate workspace permission. If either surface is
unavailable, ask the relevant Platform organization or ChatGPT workspace
administrator. This repository does not create or bypass access.

## Cost and billing

Do not assume the complete setup is free or consumes no credits:

- The tunnel layer is transport, not inference. Creating a `tunnel_id`,
  authenticating `tunnel-client` to the OpenAI control plane, and keeping that
  tunnel connected do not themselves call a model or consume model-inference
  tokens/credits. The runtime API key is used for tunnel/control-plane
  authentication; merely supplying it does not create an inference request.
- This repository and its local Python server do not independently call an
  OpenAI model merely by running the gateway.
- [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
  is an enterprise feature. Availability and commercial terms depend on the
  OpenAI organization/workspace agreement; OpenAI does not document it as an
  unconditional free service.
- When ChatGPT invokes the MCP, the ChatGPT conversation/model usage remains
  subject to that workspace's plan, usage limits, credits, and administrator
  settings. The tunnel does not erase or duplicate those charges.
- If an MCP client separately calls OpenAI models or hosted tools through the
  Responses API or another Platform API, those requests can be billed at
  [current API rates](https://developers.openai.com/api/docs/pricing). A
  tunnel runtime key must not be treated as a promise that all OpenAI API-key
  usage is free.

## Step-by-step setup

### 1. Clone and create the Python environment

```bash
git clone https://github.com/MeharPro/codex-2.0.git
cd codex-2.0
python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/pip install -r requirements.txt
./.venv/bin/playwright install chromium
```

### 2. Confirm tunnel and ChatGPT permissions

Open the official
[Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
and confirm the intended operator has:

- **Tunnels Read + Manage** in the OpenAI Platform organization to create or
  edit a tunnel.
- **Tunnels Read + Use** to run `tunnel-client` and select the tunnel from a
  supported product.
- ChatGPT developer-mode access in the target workspace. This is administered
  separately from Platform tunnel permissions.

### 3. Create the tunnel in OpenAI Platform

1. Open [Platform tunnel settings](https://platform.openai.com/settings/organization/tunnels).
2. Select the Platform organization that should own the tunnel.
3. Choose **Create tunnel**.
4. Enter a descriptive display name, such as `codex-2-macbook`. The name is for
   humans and may be chosen by you.
5. Add a clear description, such as `Local Codex 2.0 MCP gateway`.
6. Associate the target ChatGPT workspace and any Platform organization that
   should be allowed to discover or use the tunnel.
7. Create the tunnel and copy the resulting `tunnel_id`.

OpenAI generates the actual ID in the form `tunnel_...`. Do not invent an ID
from the display name. The same ID is used by `tunnel-client` and ChatGPT.
Adding another allowed organization/workspace does not create a new ID.

If your organization manages tunnels through the CLI instead, an administrator
can run `tunnel-client admin tunnels create` with a name, description, and the
intended organization/workspace IDs. This requires an admin key and tunnel
management permission; the long-lived runtime should use a separate runtime
key, not the admin key.

### 4. Install the OpenAI tunnel client

Download `tunnel-client` from the link in
[Platform tunnel settings](https://platform.openai.com/settings/organization/tunnels)
or from the
[latest public release](https://github.com/openai/tunnel-client/releases/latest).
Keep the binary somewhere on `PATH`, then verify it:

```bash
tunnel-client --version
tunnel-client help quickstart
```

If it is installed outside `PATH`, set its absolute location as
`TUNNEL_CLIENT` in `.env`.

### 5. Create and safely store your OpenAI runtime API key

1. Open the owning organization's
   [Runtime API keys](https://platform.openai.com/settings/organization/api-keys)
   page.
2. Create your own key for this runtime, using a recognizable name such as
   `codex-2-runtime`.
3. Ensure the key's principal has **Tunnels Read + Use** for the tunnel.
4. Copy the key when OpenAI displays it. Do not use an organization admin key
   as the long-lived runtime key.

Save that OpenAI Platform key outside the repository. The following zsh
commands accept it without putting the value directly in the command line:

```bash
mkdir -p "$HOME/.config/codex-mcp"
chmod 700 "$HOME/.config/codex-mcp"
read -s "runtime_key?Paste your OpenAI runtime API key: "
printf '%s' "$runtime_key" > "$HOME/.config/codex-mcp/runtime-api-key"
unset runtime_key
chmod 600 "$HOME/.config/codex-mcp/runtime-api-key"
```

This is where the user supplies their own OpenAI API key. The gateway does not
put it in `.env`, pass it to terminal tools, or commit it to Git.

### 6. Paste the tunnel ID into the ignored local configuration

```bash
cp .env.example .env
chmod 600 .env
```

Edit `.env` and replace:

```dotenv
TUNNEL_ID=tunnel_REPLACE_ME
```

with the provider-generated ID copied from Platform tunnel settings:

```dotenv
TUNNEL_ID=tunnel_YOUR_OWN_ID
```

Leave `RUNTIME_API_KEY_FILE` pointing to the mode-`600` key file created in the
previous step. Keep `.env` local—it is ignored by Git.

### 7. Install the one-line command

```bash
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/bin/codex-mcp" "$HOME/.local/bin/codex-mcp"
```

Add `~/.local/bin` to your shell `PATH` if needed:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### 8. Start the gateway in a project folder

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

For diagnostics, use the provider-supported checks:

```bash
tunnel-client runtimes status codex-tool-gateway --json
tunnel-client doctor --profile codex-tool-gateway --explain
```

Do not use `nohup` or `disown`; `codex-mcp` uses the client's managed runtime
supervision.

### 9. Connect ChatGPT

Keep `codex-mcp` running during discovery and use:

1. Enable developer mode for your ChatGPT workspace/account.
2. Open **Settings → Plugins** or
   [chatgpt.com/plugins](https://chatgpt.com/plugins).
3. Select the plus button to create a developer-mode app.
4. Under **Connection**, choose **Tunnel**.
5. Select the tunnel by its display name. If it is not listed, paste the same
   provider-generated `tunnel_id` used in `.env`.
6. Scan the MCP tools.
7. Review every action, especially terminal, filesystem, keyboard, mouse, and
   write operations.
8. Create or publish the app and explicitly connect it for your user.
9. Start a new chat, select the app, and ask it to call `gateway_info` followed
   by `terminal_status`.

If the tunnel does not appear, verify that it is associated with the target
ChatGPT workspace and that the app creator has **Tunnels Read + Use**.

ChatGPT freezes an approved snapshot of tool definitions. After updating this
server, refresh its actions in Enterprise/Edu. A published Business custom app
may need to be recreated and republished to adopt changed tools.

### 10. Connect another MCP client

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
