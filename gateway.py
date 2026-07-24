from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import Image


# Load the bundled host bridge. Advanced users may override it with
# CODEX_GATEWAY_HOST_BRIDGE.
LEGACY_MCP_DIR = Path(
    os.getenv(
        "CODEX_GATEWAY_HOST_BRIDGE",
        str(Path(__file__).with_name("host_bridge")),
    )
).expanduser().resolve()
WORKSPACE_FILE = (
    Path.home() / ".config" / "tunnel-client" / "codex-mcp-workspace"
)


def _configured_workspace() -> Path:
    configured = os.getenv("CODEX_MCP_WORKSPACE", "").strip()
    if not configured and WORKSPACE_FILE.is_file():
        configured = WORKSPACE_FILE.read_text(encoding="utf-8").strip()
    candidate = Path(configured or str(Path.home())).expanduser().resolve()
    if not candidate.is_dir():
        raise NotADirectoryError(f"Configured workspace does not exist: {candidate}")
    return candidate


GATEWAY_WORKSPACE = _configured_workspace()

# The gateway is intentionally powerful. These defaults match the user's
# request; the tunnel remains the authentication boundary.
os.environ.setdefault("ALLOW_FULL_HOST_TERMINAL", "1")
os.environ.setdefault("HOST_FILE_ROOT", "/")
os.environ.setdefault("TERMINAL_DEFAULT_CWD", str(GATEWAY_WORKSPACE))

if not (LEGACY_MCP_DIR / "ctf_browser_mcp.py").is_file():
    raise RuntimeError(
        f"MCP host bridge not found at {LEGACY_MCP_DIR}. "
        "Set CODEX_GATEWAY_HOST_BRIDGE to its directory."
    )

sys.path.insert(0, str(LEGACY_MCP_DIR))
from ctf_browser_mcp import mcp  # noqa: E402


CODEX_HOME = Path(os.getenv("CODEX_HOME", str(Path.home() / ".codex"))).expanduser()
OPERATING_POLICY_PATH = Path(__file__).with_name("OPERATING_POLICY.md")
OPERATING_POLICY = OPERATING_POLICY_PATH.read_text(encoding="utf-8")
GATEWAY_SESSION_ID = str(uuid.uuid4())
GATEWAY_SESSION_STARTED_AT = dt.datetime.now(dt.timezone.utc)
GATEWAY_HISTORY_DIR = (
    CODEX_HOME
    / "gateway_sessions"
    / GATEWAY_SESSION_STARTED_AT.strftime("%Y")
    / GATEWAY_SESSION_STARTED_AT.strftime("%m")
    / GATEWAY_SESSION_STARTED_AT.strftime("%d")
)
GATEWAY_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
GATEWAY_HISTORY_PATH = GATEWAY_HISTORY_DIR / f"{GATEWAY_SESSION_ID}.jsonl"

# FastMCP does not expose an instructions setter, but its protocol server reads
# this field for every initialize response. This gives all MCP clients the same
# gateway policy automatically. Host system/developer prompts still outrank it.
mcp._mcp_server.instructions = OPERATING_POLICY  # noqa: SLF001

SKILL_ROOTS = [
    CODEX_HOME / "skills",
    Path.home() / ".agents" / "skills",
    CODEX_HOME / "plugins" / "cache",
]

CLICLICK = shutil.which("cliclick") or "/opt/homebrew/bin/cliclick"
SCREENCAPTURE = "/usr/sbin/screencapture"
OSASCRIPT = "/usr/bin/osascript"
OPEN = "/usr/bin/open"
DESKTOP_CAPTURE_DIR = Path.home() / ".codex-gateway" / "screenshots"
DESKTOP_CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

RUNNING_APPS_JXA = r"""
ObjC.import("AppKit");
const apps = $.NSWorkspace.sharedWorkspace.runningApplications.js.map(app => ({
  name: ObjC.unwrap(app.localizedName) || "",
  bundle_id: ObjC.unwrap(app.bundleIdentifier) || "",
  pid: Number(app.processIdentifier),
  active: Boolean(app.active),
  hidden: Boolean(app.hidden),
  terminated: Boolean(app.terminated)
}));
JSON.stringify(apps);
"""

ACCESSIBILITY_TREE_JXA = r"""
function run(argv) {
  const appName = argv[0];
  const maxDepth = Math.max(1, Math.min(Number(argv[1] || 6), 12));
  const maxNodes = Math.max(1, Math.min(Number(argv[2] || 800), 3000));
  const se = Application("System Events");
  const proc = se.applicationProcesses.byName(appName);
  if (!proc.exists()) throw new Error("Application process not found: " + appName);

  function get(fn, fallback) {
    try {
      const value = fn();
      return value === undefined ? fallback : value;
    } catch (_) {
      return fallback;
    }
  }

  const nodes = [];
  function walk(element, depth, path) {
    if (nodes.length >= maxNodes) return;
    const position = get(() => element.position(), null);
    const size = get(() => element.size(), null);
    nodes.push({
      index: nodes.length,
      path,
      role: get(() => element.role(), ""),
      subrole: get(() => element.subrole(), ""),
      name: get(() => element.name(), ""),
      description: get(() => element.description(), ""),
      value: get(() => element.value(), null),
      enabled: get(() => Boolean(element.enabled()), null),
      position,
      size
    });
    if (depth >= maxDepth) return;
    const children = get(() => element.uiElements(), []);
    for (let i = 0; i < children.length && nodes.length < maxNodes; i++) {
      walk(children[i], depth + 1, path.concat(i));
    }
  }

  const windows = get(() => proc.windows(), []);
  for (let i = 0; i < windows.length && nodes.length < maxNodes; i++) {
    walk(windows[i], 0, [i]);
  }
  return JSON.stringify({
    app: appName,
    frontmost: get(() => Boolean(proc.frontmost()), false),
    visible: get(() => Boolean(proc.visible()), false),
    node_count: nodes.length,
    truncated: nodes.length >= maxNodes,
    nodes
  });
}
"""


async def _run_process(
    args: list[str],
    *,
    timeout_seconds: float = 30,
) -> tuple[str, str]:
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout_seconds
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise TimeoutError(f"Command timed out after {timeout_seconds}s: {args[0]}")
    out = stdout.decode("utf-8", errors="replace").strip()
    err = stderr.decode("utf-8", errors="replace").strip()
    if process.returncode != 0:
        detail = err or out or f"exit code {process.returncode}"
        raise RuntimeError(f"{Path(args[0]).name} failed: {detail}")
    return out, err


def _redact_audit_value(value: Any, key: str = "") -> Any:
    sensitive_markers = {
        "api_key",
        "authorization",
        "cookie",
        "credential",
        "password",
        "secret",
        "token",
    }
    if any(marker in key.lower() for marker in sensitive_markers):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(child_key): _redact_audit_value(child_value, str(child_key))
            for child_key, child_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_audit_value(item, key) for item in value[:100]]
    if isinstance(value, str):
        if len(value) > 2_000:
            return value[:2_000] + f"...[trimmed {len(value) - 2_000} chars]"
        return value
    return value


def _sensitive_text_summary(value: Any) -> Any:
    if not isinstance(value, str):
        return "[REDACTED]"
    return {
        "redacted": True,
        "characters": len(value),
        "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
    }


def _audit_arguments(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    safe_arguments = _redact_audit_value(arguments)
    sensitive_fields_by_tool = {
        "browser_evaluate": {"expression"},
        "browser_fill": {"value"},
        "browser_set_cookie": {"value"},
        "desktop_type_text": {"text"},
        "gateway_session_note": {"text"},
        "host_write_base64": {"data"},
        "host_write_text": {"text"},
        "terminal_exec": {"command", "extra_env"},
        "terminal_start": {"initial_command", "extra_env"},
        "terminal_write": {"data"},
    }
    for field in sensitive_fields_by_tool.get(tool, set()):
        if field in arguments:
            safe_arguments[field] = _sensitive_text_summary(arguments[field])
    return safe_arguments


def _append_gateway_history(event: dict[str, Any]) -> None:
    record = {
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "gateway_session_id": GATEWAY_SESSION_ID,
        "workspace": str(GATEWAY_WORKSPACE),
        **event,
    }
    with GATEWAY_HISTORY_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")


def _safe_read(path: Path, max_chars: int) -> tuple[str, bool]:
    text = path.read_text(encoding="utf-8", errors="replace")
    truncated = len(text) > max_chars
    return text[:max_chars], truncated


def _skill_entries() -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    seen: set[Path] = set()
    for root in SKILL_ROOTS:
        if not root.exists():
            continue
        for skill_file in root.rglob("SKILL.md"):
            resolved = skill_file.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            rel = resolved.relative_to(root.resolve())
            entries.append(
                {
                    "name": str(rel.parent).replace("/", ":"),
                    "path": str(resolved),
                    "root": str(root.resolve()),
                }
            )
    return sorted(entries, key=lambda item: (item["name"].lower(), item["path"]))


def _resolve_skill(name_or_path: str) -> Path:
    requested = Path(name_or_path).expanduser()
    if requested.is_absolute():
        candidate = requested if requested.name == "SKILL.md" else requested / "SKILL.md"
        if candidate.is_file():
            return candidate.resolve()

    normalized = name_or_path.strip().lower()
    matches = [
        Path(item["path"])
        for item in _skill_entries()
        if item["name"].lower() == normalized
        or Path(item["path"]).parent.name.lower() == normalized
    ]
    if not matches:
        raise FileNotFoundError(f"No installed Codex skill matched {name_or_path!r}")
    if len(matches) > 1:
        raise ValueError(
            "Skill name is ambiguous; use an absolute path. Matches: "
            + ", ".join(str(path) for path in matches[:20])
        )
    return matches[0]


def _latest_tool_cache() -> Path | None:
    cache_dir = CODEX_HOME / "cache" / "codex_apps_tools"
    files = list(cache_dir.glob("*.json")) if cache_dir.exists() else []
    return max(files, key=lambda path: path.stat().st_mtime) if files else None


@mcp.tool()
async def gateway_info() -> dict[str, Any]:
    """Describe this gateway's access and the boundary of what can be exported."""
    cache = _latest_tool_cache()
    return {
        "name": "Codex Host Tool Gateway",
        "host": "local Mac user session",
        "workspace": str(GATEWAY_WORKSPACE),
        "gateway_session_id": GATEWAY_SESSION_ID,
        "gateway_history_path": str(GATEWAY_HISTORY_PATH),
        "history_scope": (
            "MCP tool activity and explicit gateway session notes; the MCP "
            "server does not receive the complete ChatGPT transcript."
        ),
        "terminal_access": True,
        "filesystem_root": os.environ["HOST_FILE_ROOT"],
        "browser_bridge": str(LEGACY_MCP_DIR),
        "playwright_browser_tools": True,
        "direct_desktop_automation_tools": True,
        "direct_desktop_automation_backend": (
            "macOS screencapture + Accessibility/JXA + cliclick"
        ),
        "computer_use_tools": False,
        "computer_use_reason": (
            "The local Computer Use server authenticates its signed Codex caller "
            "and rejects standalone MCP processes."
        ),
        "codex_chrome_extension_tools": False,
        "codex_chrome_extension_reason": (
            "The Chrome plugin requires Codex's trusted browser-client and "
            "persistent Node runtime; it is not a standalone MCP server."
        ),
        "codex_home": str(CODEX_HOME),
        "installed_skill_count": len(_skill_entries()),
        "codex_tool_cache": str(cache) if cache else None,
        "important_boundary": (
            "Local host tools, files, and skill instructions are executable/readable. "
            "Codex/ChatGPT connector OAuth sessions are held by OpenAI and are not "
            "delegable through this local MCP; connect those apps directly in ChatGPT."
        ),
    }


@mcp.tool()
async def gateway_operating_policy() -> dict[str, Any]:
    """Read the safety and operating policy delivered during MCP initialization."""
    return {
        "path": str(OPERATING_POLICY_PATH),
        "policy": OPERATING_POLICY,
        "priority_note": (
            "This is MCP server guidance. The connected model's system and "
            "developer instructions have higher priority."
        ),
    }


@mcp.tool()
async def gateway_session_note(
    text: str,
    kind: str = "note",
) -> dict[str, Any]:
    """Save a goal, decision, checkpoint, or outcome in the local session journal."""
    normalized_kind = kind.strip().lower()
    if normalized_kind not in {
        "goal",
        "note",
        "decision",
        "checkpoint",
        "outcome",
    }:
        raise ValueError(
            "kind must be goal, note, decision, checkpoint, or outcome"
        )
    _append_gateway_history(
        {
            "event": "session_note",
            "kind": normalized_kind,
            "text": _redact_audit_value(text, "text"),
        }
    )
    return {
        "ok": True,
        "session_id": GATEWAY_SESSION_ID,
        "history_path": str(GATEWAY_HISTORY_PATH),
    }


@mcp.tool()
async def gateway_session_history(limit: int = 100) -> dict[str, Any]:
    """Read recent records from the current workspace-bound gateway session."""
    if not GATEWAY_HISTORY_PATH.is_file():
        return {
            "session_id": GATEWAY_SESSION_ID,
            "workspace": str(GATEWAY_WORKSPACE),
            "records": [],
        }
    lines = GATEWAY_HISTORY_PATH.read_text(encoding="utf-8").splitlines()
    bounded = lines[-max(1, min(limit, 1000)) :]
    return {
        "session_id": GATEWAY_SESSION_ID,
        "workspace": str(GATEWAY_WORKSPACE),
        "history_path": str(GATEWAY_HISTORY_PATH),
        "records": [json.loads(line) for line in bounded],
    }


@mcp.tool()
async def desktop_capabilities() -> dict[str, Any]:
    """Report direct macOS automation backends and permission readiness."""
    accessibility_out = ""
    accessibility_error = ""
    try:
        accessibility_out, _ = await _run_process(
            [
                OSASCRIPT,
                "-e",
                'tell application "System Events" to return UI elements enabled',
            ],
            timeout_seconds=10,
        )
    except Exception as exc:
        accessibility_error = str(exc)
    return {
        "direct_outer_model_control": True,
        "cliclick": CLICLICK if Path(CLICLICK).is_file() else None,
        "screencapture": (
            SCREENCAPTURE if Path(SCREENCAPTURE).is_file() else None
        ),
        "accessibility_enabled": accessibility_out.strip().lower() == "true",
        "accessibility_probe_error": accessibility_error or None,
        "permission_note": (
            "If actions fail, grant Accessibility and Screen & System Audio "
            "Recording permission to tunnel-client/the launching terminal in "
            "System Settings → Privacy & Security."
        ),
    }


@mcp.tool()
async def desktop_list_apps() -> dict[str, Any]:
    """List running macOS applications without using Codex Computer Use."""
    output, _ = await _run_process(
        [OSASCRIPT, "-l", "JavaScript", "-e", RUNNING_APPS_JXA],
        timeout_seconds=15,
    )
    apps = json.loads(output)
    return {"apps": apps, "total": len(apps)}


@mcp.tool()
async def desktop_activate_app(app: str) -> dict[str, Any]:
    """Launch or bring a macOS application to the foreground by name."""
    if not app.strip():
        raise ValueError("app cannot be empty")
    await _run_process([OPEN, "-a", app], timeout_seconds=20)
    return {"ok": True, "app": app}


@mcp.tool()
async def desktop_accessibility_tree(
    app: str,
    max_depth: int = 6,
    max_nodes: int = 800,
) -> dict[str, Any]:
    """Read a bounded macOS Accessibility tree for a running application."""
    if not app.strip():
        raise ValueError("app cannot be empty")
    output, _ = await _run_process(
        [
            OSASCRIPT,
            "-l",
            "JavaScript",
            "-e",
            ACCESSIBILITY_TREE_JXA,
            app,
            str(max_depth),
            str(max_nodes),
        ],
        timeout_seconds=30,
    )
    return json.loads(output)


@mcp.tool()
async def desktop_screenshot() -> Image:
    """Capture all displays and return a PNG image directly to the model."""
    handle, raw_path = tempfile.mkstemp(
        prefix="desktop-", suffix=".png", dir=DESKTOP_CAPTURE_DIR
    )
    os.close(handle)
    path = Path(raw_path)
    try:
        await _run_process(
            [SCREENCAPTURE, "-x", "-t", "png", str(path)],
            timeout_seconds=20,
        )
        if not path.is_file() or path.stat().st_size == 0:
            raise RuntimeError("screencapture produced no image")
        return Image(path=path)
    finally:
        # FastMCP converts Image to content after the function returns, so retain
        # recent captures for diagnostics instead of deleting too early.
        captures = sorted(
            DESKTOP_CAPTURE_DIR.glob("desktop-*.png"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        for old_capture in captures[20:]:
            old_capture.unlink(missing_ok=True)


@mcp.tool()
async def desktop_mouse_position() -> dict[str, Any]:
    """Read the current global mouse position."""
    output, _ = await _run_process([CLICLICK, "p:."], timeout_seconds=10)
    parts = output.replace(" ", "").split(",")
    if len(parts) != 2:
        return {"raw": output}
    return {"x": int(parts[0]), "y": int(parts[1])}


@mcp.tool()
async def desktop_click(
    x: int,
    y: int,
    button: str = "left",
    click_count: int = 1,
) -> dict[str, Any]:
    """Click screen coordinates directly using the outside model's tool call."""
    normalized_button = button.strip().lower()
    if normalized_button not in {"left", "right"}:
        raise ValueError("button must be left or right")
    if click_count not in {1, 2, 3}:
        raise ValueError("click_count must be 1, 2, or 3")
    if normalized_button == "right":
        if click_count != 1:
            raise ValueError("right-click supports click_count=1 only")
        command = f"rc:{x},{y}"
    else:
        command = {1: "c", 2: "dc", 3: "tc"}[click_count] + f":{x},{y}"
    await _run_process([CLICLICK, command], timeout_seconds=10)
    return {
        "ok": True,
        "x": x,
        "y": y,
        "button": normalized_button,
        "click_count": click_count,
    }


@mcp.tool()
async def desktop_move(x: int, y: int) -> dict[str, Any]:
    """Move the global mouse cursor to screen coordinates."""
    await _run_process([CLICLICK, f"m:{x},{y}"], timeout_seconds=10)
    return {"ok": True, "x": x, "y": y}


@mcp.tool()
async def desktop_drag(
    from_x: int,
    from_y: int,
    to_x: int,
    to_y: int,
) -> dict[str, Any]:
    """Drag from one pair of screen coordinates to another."""
    await _run_process(
        [
            CLICLICK,
            f"dd:{from_x},{from_y}",
            f"dm:{to_x},{to_y}",
            f"du:{to_x},{to_y}",
        ],
        timeout_seconds=15,
    )
    return {
        "ok": True,
        "from": {"x": from_x, "y": from_y},
        "to": {"x": to_x, "y": to_y},
    }


@mcp.tool()
async def desktop_type_text(text: str) -> dict[str, Any]:
    """Type literal text into the currently focused macOS application."""
    await _run_process([CLICLICK, f"t:{text}"], timeout_seconds=30)
    return {"ok": True, "characters_typed": len(text)}


@mcp.tool()
async def desktop_press_key(
    key: str,
    modifiers: list[str] | None = None,
) -> dict[str, Any]:
    """Press a supported key with optional cmd/alt/ctrl/shift modifiers."""
    supported_keys = {
        "arrow-down",
        "arrow-left",
        "arrow-right",
        "arrow-up",
        "delete",
        "end",
        "enter",
        "esc",
        "fwd-delete",
        "home",
        "page-down",
        "page-up",
        "return",
        "space",
        "tab",
    } | {f"f{number}" for number in range(1, 17)}
    normalized_key = key.strip().lower()
    if normalized_key not in supported_keys:
        raise ValueError(f"Unsupported key. Choose one of {sorted(supported_keys)}")
    normalized_modifiers = [
        modifier.strip().lower() for modifier in (modifiers or [])
    ]
    allowed_modifiers = {"cmd", "alt", "ctrl", "shift", "fn"}
    if any(modifier not in allowed_modifiers for modifier in normalized_modifiers):
        raise ValueError(
            f"modifiers must be chosen from {sorted(allowed_modifiers)}"
        )
    commands: list[str] = []
    if normalized_modifiers:
        joined = ",".join(normalized_modifiers)
        commands.append(f"kd:{joined}")
    commands.append(f"kp:{normalized_key}")
    if normalized_modifiers:
        commands.append(f"ku:{','.join(normalized_modifiers)}")
    await _run_process([CLICLICK, *commands], timeout_seconds=10)
    return {
        "ok": True,
        "key": normalized_key,
        "modifiers": normalized_modifiers,
    }


@mcp.tool()
async def codex_skills_list(query: str = "", limit: int = 250) -> dict[str, Any]:
    """List installed Codex skills and their on-disk SKILL.md paths."""
    needle = query.strip().lower()
    entries = _skill_entries()
    if needle:
        entries = [
            item
            for item in entries
            if needle in item["name"].lower() or needle in item["path"].lower()
        ]
    return {"skills": entries[: max(1, min(limit, 1000))], "total": len(entries)}


@mcp.tool()
async def codex_skill_read(
    name_or_path: str,
    relative_path: str = "SKILL.md",
    max_chars: int = 100_000,
) -> dict[str, Any]:
    """Read an installed skill or a file contained in that skill directory."""
    skill_file = _resolve_skill(name_or_path)
    skill_dir = skill_file.parent.resolve()
    target = (skill_dir / relative_path).resolve()
    try:
        target.relative_to(skill_dir)
    except ValueError as exc:
        raise PermissionError("relative_path must stay inside the selected skill") from exc
    if not target.is_file():
        raise FileNotFoundError(str(target))
    text, truncated = _safe_read(target, max(1_000, min(max_chars, 500_000)))
    return {"path": str(target), "text": text, "truncated": truncated}


@mcp.tool()
async def codex_plugins_list(query: str = "", limit: int = 250) -> dict[str, Any]:
    """List locally cached Codex plugin manifests without exposing credentials."""
    root = CODEX_HOME / "plugins" / "cache"
    needle = query.strip().lower()
    plugins: list[dict[str, Any]] = []
    if root.exists():
        for manifest in root.rglob(".codex-plugin/plugin.json"):
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            item = {
                "name": data.get("name"),
                "version": data.get("version"),
                "description": data.get("description"),
                "path": str(manifest.resolve()),
                "has_apps": bool(data.get("apps")),
                "has_skills": bool(data.get("skills")),
                "has_mcp_servers": bool(data.get("mcpServers") or data.get("mcp_servers")),
            }
            haystack = json.dumps(item).lower()
            if not needle or needle in haystack:
                plugins.append(item)
    plugins.sort(key=lambda item: (str(item["name"]).lower(), str(item["version"])))
    return {"plugins": plugins[: max(1, min(limit, 1000))], "total": len(plugins)}


@mcp.tool()
async def codex_tool_catalog(
    query: str = "",
    connector: str = "",
    include_input_schema: bool = True,
    limit: int = 200,
) -> dict[str, Any]:
    """Inspect Codex's cached connector tool schemas; this does not invoke them."""
    cache = _latest_tool_cache()
    if cache is None:
        return {"tools": [], "total": 0, "cache": None}
    data = json.loads(cache.read_text(encoding="utf-8"))
    needle = query.strip().lower()
    connector_needle = connector.strip().lower()
    tools: list[dict[str, Any]] = []
    for entry in data.get("tools", []):
        tool = entry.get("tool") or {}
        connector_name = str(entry.get("connector_name") or "")
        item = {
            "connector": connector_name,
            "namespace": entry.get("tool_namespace"),
            "name": tool.get("name") or entry.get("tool_name"),
            "title": tool.get("title"),
            "description": tool.get("description"),
        }
        if include_input_schema:
            item["input_schema"] = tool.get("inputSchema")
        haystack = json.dumps(item).lower()
        if connector_needle and connector_needle not in connector_name.lower():
            continue
        if needle and needle not in haystack:
            continue
        tools.append(item)
    tools.sort(key=lambda item: (str(item["connector"]).lower(), str(item["name"])))
    return {
        "tools": tools[: max(1, min(limit, 1000))],
        "total": len(tools),
        "cache": str(cache),
        "invocation_supported": False,
        "reason": "Connector credentials and calls are owned by the OpenAI host.",
    }


_append_gateway_history(
    {
        "event": "session_started",
        "pid": os.getpid(),
        "tool_server": "Codex Host Tool Gateway",
    }
)

_original_call_tool = mcp._tool_manager.call_tool  # noqa: SLF001


async def _audited_call_tool(
    name: str,
    arguments: dict[str, Any],
    context: Any = None,
    convert_result: bool = False,
) -> Any:
    started = time.monotonic()
    _append_gateway_history(
        {
            "event": "tool_call_started",
            "tool": name,
            "arguments": _audit_arguments(name, arguments),
        }
    )
    try:
        result = await _original_call_tool(
            name,
            arguments,
            context=context,
            convert_result=convert_result,
        )
    except Exception as exc:
        _append_gateway_history(
            {
                "event": "tool_call_finished",
                "tool": name,
                "ok": False,
                "duration_ms": round((time.monotonic() - started) * 1000, 3),
                "error_type": type(exc).__name__,
                "error": _redact_audit_value(str(exc), "error"),
            }
        )
        raise
    _append_gateway_history(
        {
            "event": "tool_call_finished",
            "tool": name,
            "ok": True,
            "duration_ms": round((time.monotonic() - started) * 1000, 3),
        }
    )
    return result


mcp._tool_manager.call_tool = _audited_call_tool  # type: ignore[method-assign]  # noqa: SLF001


if __name__ == "__main__":
    mcp.run(transport="stdio")
