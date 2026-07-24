from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
import shutil
import signal
import sys
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    async_playwright,
)

CDP_URL = os.getenv("CDP_URL", "http://127.0.0.1:9222")
DOWNLOAD_DIR = Path(
    os.getenv("CTF_DOWNLOAD_DIR", str(Path.home() / "htn-ctf-downloads"))
).expanduser().resolve()
DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)


HOST_FILE_ROOT = Path(
    os.getenv("HOST_FILE_ROOT", str(Path.home()))
).expanduser().resolve()
HOST_FILE_ROOT.mkdir(parents=True, exist_ok=True)

TERMINAL_DEFAULT_CWD = Path(
    os.getenv("TERMINAL_DEFAULT_CWD", str(Path.home()))
).expanduser().resolve()
TERMINAL_SHELL = os.getenv("TERMINAL_SHELL", "/bin/zsh")
ALLOW_FULL_HOST_TERMINAL = os.getenv(
    "ALLOW_FULL_HOST_TERMINAL", "0"
).strip().lower() in {"1", "true", "yes", "on"}
TERMINAL_SESSION_BUFFER_BYTES = max(
    100_000,
    int(os.getenv("TERMINAL_SESSION_BUFFER_BYTES", "2000000")),
)

mcp = FastMCP(
    "HTN CTF Browser",
    instructions=(
        "Control the dedicated Chrome session connected through CDP for the "
        "authorized Hack the North CTF. Host file and terminal tools are also "
        "available when explicitly enabled by the user. Treat terminal access "
        "as full user-level access to this Mac. Avoid unrelated files, secrets, "
        "accounts, and systems unless the user explicitly directs otherwise."
    ),
)

_pw: Playwright | None = None
_browser: Browser | None = None
_context: BrowserContext | None = None
_page: Page | None = None
_lock = asyncio.Lock()
_network: list[dict[str, Any]] = []
_attached_pages: set[int] = set()


_terminal_sessions: dict[str, dict[str, Any]] = {}
_terminal_sessions_lock = asyncio.Lock()


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _trim(value: str, limit: int = 50_000) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"\n...[trimmed {len(value) - limit} characters]"


def _safe_filename(name: str) -> str:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
    cleaned = "".join(ch if ch in allowed else "_" for ch in name)
    return cleaned[:180] or f"download-{int(time.time())}"


def _attach_network(page: Page) -> None:
    key = id(page)
    if key in _attached_pages:
        return
    _attached_pages.add(key)

    def on_request(request: Any) -> None:
        _network.append(
            {
                "type": "request",
                "method": request.method,
                "url": request.url,
                "resource_type": request.resource_type,
                "timestamp": time.time(),
            }
        )
        if len(_network) > 2000:
            del _network[:500]

    def on_response(response: Any) -> None:
        _network.append(
            {
                "type": "response",
                "status": response.status,
                "url": response.url,
                "timestamp": time.time(),
            }
        )
        if len(_network) > 2000:
            del _network[:500]

    page.on("request", on_request)
    page.on("response", on_response)


async def _ensure_page() -> Page:
    global _pw, _browser, _context, _page

    if _pw is None:
        _pw = await async_playwright().start()

    if _browser is None or not _browser.is_connected():
        _log(f"Connecting to Chrome over CDP: {CDP_URL}")
        _browser = await _pw.chromium.connect_over_cdp(CDP_URL)

    contexts = _browser.contexts
    if not contexts:
        raise RuntimeError(
            "Chrome is connected but no browser context exists. "
            "Open at least one tab in the dedicated Chrome window."
        )

    _context = contexts[0]

    available_pages = [p for p in _context.pages if not p.is_closed()]
    if _page is None or _page.is_closed():
        _page = available_pages[-1] if available_pages else await _context.new_page()

    _attach_network(_page)
    return _page


async def _find_locator(page: Page, target: str):
    target = target.strip()
    if not target:
        raise ValueError("target cannot be empty")

    try:
        locator = page.locator(target)
        if await locator.count() > 0:
            return locator.first
    except Exception:
        pass

    exact = page.get_by_text(target, exact=True)
    if await exact.count() > 0:
        return exact.first

    partial = page.get_by_text(target, exact=False)
    if await partial.count() > 0:
        return partial.first

    raise ValueError(f"No element matched target: {target!r}")


def _terminal_enabled() -> None:
    if not ALLOW_FULL_HOST_TERMINAL:
        raise PermissionError(
            "Full host terminal access is disabled. Restart tunnel-client with "
            "ALLOW_FULL_HOST_TERMINAL=1 in its environment."
        )


def _resolve_host_path(path: str, *, must_exist: bool = False) -> Path:
    raw = path.strip() or "."
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = HOST_FILE_ROOT / candidate
    resolved = candidate.resolve(strict=False)

    try:
        resolved.relative_to(HOST_FILE_ROOT)
    except ValueError as exc:
        raise PermissionError(
            f"Path is outside HOST_FILE_ROOT={HOST_FILE_ROOT}. "
            "Set HOST_FILE_ROOT=/ before starting the tunnel to permit the "
            "entire filesystem."
        ) from exc

    if must_exist and not resolved.exists():
        raise FileNotFoundError(str(resolved))

    return resolved


def _resolve_terminal_cwd(cwd: str) -> Path:
    candidate = Path(cwd.strip() or str(TERMINAL_DEFAULT_CWD)).expanduser()
    resolved = candidate.resolve(strict=False)
    if not resolved.exists():
        raise FileNotFoundError(str(resolved))
    if not resolved.is_dir():
        raise NotADirectoryError(str(resolved))
    return resolved


def _terminal_environment(extra_env: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ)

    # Do not leak connector/runtime credentials into child shells by default.
    protected_names = {
        "CONTROL_PLANE_API_KEY",
        "OPENAI_API_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "ANTHROPIC_API_KEY",
    }
    for name in protected_names:
        env.pop(name, None)

    for name in list(env):
        upper = name.upper()
        if upper.startswith("AWS_") and (
            "KEY" in upper or "TOKEN" in upper or "SECRET" in upper
        ):
            env.pop(name, None)

    if extra_env:
        for key, value in extra_env.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise TypeError("extra_env must map strings to strings")
            env[key] = value

    env.setdefault("TERM", "xterm-256color")
    return env


def _decode_output(data: bytes, max_chars: int) -> tuple[str, bool]:
    text = data.decode("utf-8", errors="replace")
    return text[:max_chars], len(text) > max_chars


async def _terminate_process_group(
    process: asyncio.subprocess.Process,
    sig: signal.Signals = signal.SIGTERM,
) -> None:
    if process.returncode is not None:
        return
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        return


async def _terminal_output_pump(session_id: str) -> None:
    session = _terminal_sessions.get(session_id)
    if not session:
        return

    process: asyncio.subprocess.Process = session["process"]
    stream = process.stdout
    if stream is None:
        return

    try:
        while True:
            chunk = await stream.read(8192)
            if not chunk:
                break

            async with session["buffer_lock"]:
                buffer: bytearray = session["buffer"]
                buffer.extend(chunk)

                overflow = len(buffer) - TERMINAL_SESSION_BUFFER_BYTES
                if overflow > 0:
                    del buffer[:overflow]
                    session["read_offset"] = max(
                        0, session["read_offset"] - overflow
                    )
    finally:
        await process.wait()
        session["finished_at"] = time.time()
        session["exit_code"] = process.returncode


def _terminal_session_snapshot(
    session_id: str,
    session: dict[str, Any],
) -> dict[str, Any]:
    process: asyncio.subprocess.Process = session["process"]
    return {
        "session_id": session_id,
        "pid": process.pid,
        "running": process.returncode is None,
        "exit_code": process.returncode,
        "cwd": session["cwd"],
        "started_at": session["started_at"],
        "finished_at": session.get("finished_at"),
        "initial_command": session.get("initial_command", ""),
    }


@mcp.tool()
async def browser_status() -> dict[str, Any]:
    """Read the current browser tab, title, URL, and open tabs."""
    async with _lock:
        page = await _ensure_page()
        assert _context is not None
        tabs = []
        for index, tab in enumerate(_context.pages):
            if tab.is_closed():
                continue
            try:
                tabs.append(
                    {
                        "index": index,
                        "url": tab.url,
                        "title": await tab.title(),
                        "active": tab is page,
                    }
                )
            except Exception as exc:
                tabs.append(
                    {
                        "index": index,
                        "url": tab.url,
                        "title": "",
                        "active": tab is page,
                        "error": str(exc),
                    }
                )
        return {
            "connected": True,
            "cdp_url": CDP_URL,
            "url": page.url,
            "title": await page.title(),
            "tabs": tabs,
        }


@mcp.tool()
async def browser_navigate(
    url: str,
    wait_until: str = "domcontentloaded",
    timeout_ms: int = 30_000,
) -> dict[str, Any]:
    """Navigate the dedicated browser tab to a URL."""
    async with _lock:
        page = await _ensure_page()
        await page.goto(url, wait_until=wait_until, timeout=timeout_ms)
        return {
            "ok": True,
            "url": page.url,
            "title": await page.title(),
        }


@mcp.tool()
async def browser_set_cookie(
    name: str,
    value: str,
    domain: str,
    path: str = "/",
    secure: bool = True,
    same_site: str = "Lax",
    max_age_seconds: int = 315_360_000,
) -> dict[str, Any]:
    """Set a cookie in the dedicated browser context."""
    async with _lock:
        await _ensure_page()
        assert _context is not None
        same_site_value = same_site.capitalize()
        if same_site_value not in {"Lax", "Strict", "None"}:
            raise ValueError("same_site must be Lax, Strict, or None")
        cookie = {
            "name": name,
            "value": value,
            "domain": domain,
            "path": path,
            "secure": secure,
            "sameSite": same_site_value,
            "expires": time.time() + max_age_seconds,
        }
        await _context.add_cookies([cookie])
        return {"ok": True, "cookie": cookie}


@mcp.tool()
async def browser_snapshot(max_text_chars: int = 40_000) -> dict[str, Any]:
    """Read visible page text and a structured list of interactive elements."""
    async with _lock:
        page = await _ensure_page()
        payload = await page.evaluate(
            """
            () => {
              const visible = (el) => {
                const style = getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                return style.visibility !== 'hidden' &&
                       style.display !== 'none' &&
                       rect.width > 0 &&
                       rect.height > 0;
              };

              const nodes = Array.from(document.querySelectorAll(
                'a,button,input,textarea,select,[role="button"],[role="link"],[onclick]'
              )).filter(visible).slice(0, 400);

              const interactive = nodes.map((el, index) => ({
                index,
                tag: el.tagName.toLowerCase(),
                text: (el.innerText || el.value || el.getAttribute('aria-label') || '')
                  .trim().slice(0, 500),
                id: el.id || null,
                name: el.getAttribute('name'),
                type: el.getAttribute('type'),
                href: el.href || null,
                role: el.getAttribute('role'),
                ariaLabel: el.getAttribute('aria-label'),
                placeholder: el.getAttribute('placeholder'),
                selectorHint:
                  el.id ? `#${CSS.escape(el.id)}` :
                  el.getAttribute('name') ? `${el.tagName.toLowerCase()}[name="${el.getAttribute('name')}"]` :
                  null
              }));

              return {
                bodyText: document.body?.innerText || '',
                interactive
              };
            }
            """
        )
        return {
            "url": page.url,
            "title": await page.title(),
            "text": _trim(payload.get("bodyText", ""), max_text_chars),
            "interactive": payload.get("interactive", []),
        }


@mcp.tool()
async def browser_html(max_chars: int = 60_000) -> dict[str, Any]:
    """Read the current page HTML, trimmed to a safe response size."""
    async with _lock:
        page = await _ensure_page()
        html = await page.content()
        return {
            "url": page.url,
            "html": _trim(html, max_chars),
            "original_length": len(html),
        }


@mcp.tool()
async def browser_click(
    target: str,
    timeout_ms: int = 15_000,
) -> dict[str, Any]:
    """Click an element using a CSS selector, Playwright selector, or visible text."""
    async with _lock:
        page = await _ensure_page()
        locator = await _find_locator(page, target)
        await locator.click(timeout=timeout_ms)
        await page.wait_for_timeout(300)
        return {
            "ok": True,
            "url": page.url,
            "title": await page.title(),
        }


@mcp.tool()
async def browser_fill(
    target: str,
    value: str,
    timeout_ms: int = 15_000,
) -> dict[str, Any]:
    """Fill an input or textarea using a selector or visible label/text."""
    async with _lock:
        page = await _ensure_page()
        locator = await _find_locator(page, target)
        await locator.fill(value, timeout=timeout_ms)
        return {"ok": True, "target": target, "value_length": len(value)}


@mcp.tool()
async def browser_press(
    key: str,
    target: str = "body",
    timeout_ms: int = 15_000,
) -> dict[str, Any]:
    """Press a keyboard key on a target element."""
    async with _lock:
        page = await _ensure_page()
        locator = await _find_locator(page, target)
        await locator.press(key, timeout=timeout_ms)
        return {"ok": True, "key": key, "target": target}


@mcp.tool()
async def browser_evaluate(expression: str) -> dict[str, Any]:
    """Evaluate JavaScript inside the current page only."""
    async with _lock:
        page = await _ensure_page()
        result = await page.evaluate(expression)
        try:
            json.dumps(result)
            safe_result = result
        except TypeError:
            safe_result = repr(result)
        return {"ok": True, "result": safe_result}


@mcp.tool()
async def browser_cookies(urls: list[str] | None = None) -> dict[str, Any]:
    """Read cookies from the dedicated browser context."""
    async with _lock:
        await _ensure_page()
        assert _context is not None
        cookies = await _context.cookies(urls or [])
        return {"cookies": cookies}


@mcp.tool()
async def browser_storage() -> dict[str, Any]:
    """Read localStorage and sessionStorage for the current page."""
    async with _lock:
        page = await _ensure_page()
        result = await page.evaluate(
            """
            () => ({
              localStorage: Object.fromEntries(
                Array.from({length: localStorage.length}, (_, i) => {
                  const k = localStorage.key(i);
                  return [k, localStorage.getItem(k)];
                })
              ),
              sessionStorage: Object.fromEntries(
                Array.from({length: sessionStorage.length}, (_, i) => {
                  const k = sessionStorage.key(i);
                  return [k, sessionStorage.getItem(k)];
                })
              )
            })
            """
        )
        return {"url": page.url, **result}


@mcp.tool()
async def browser_network(
    limit: int = 200,
    contains: str = "",
) -> dict[str, Any]:
    """Read recent request and response metadata captured by the browser controller."""
    async with _lock:
        await _ensure_page()
        rows = _network
        if contains:
            needle = contains.lower()
            rows = [row for row in rows if needle in str(row.get("url", "")).lower()]
        return {"events": rows[-max(1, min(limit, 1000)) :]}


@mcp.tool()
async def browser_clear_network() -> dict[str, Any]:
    """Clear captured network metadata."""
    async with _lock:
        count = len(_network)
        _network.clear()
        return {"ok": True, "cleared": count}


@mcp.tool()
async def browser_screenshot(
    full_page: bool = False,
    quality: int = 70,
) -> dict[str, Any]:
    """Capture a JPEG screenshot and return it as base64 plus a local path."""
    async with _lock:
        page = await _ensure_page()
        quality = max(20, min(quality, 90))
        filename = f"screenshot-{int(time.time())}.jpg"
        path = DOWNLOAD_DIR / filename
        data = await page.screenshot(
            path=str(path),
            type="jpeg",
            quality=quality,
            full_page=full_page,
        )
        return {
            "ok": True,
            "mime_type": "image/jpeg",
            "path": str(path),
            "base64": base64.b64encode(data).decode("ascii"),
        }


@mcp.tool()
async def browser_download_click(
    target: str,
    timeout_ms: int = 30_000,
) -> dict[str, Any]:
    """Click an element and capture the resulting browser download."""
    async with _lock:
        page = await _ensure_page()
        locator = await _find_locator(page, target)
        async with page.expect_download(timeout=timeout_ms) as download_info:
            await locator.click(timeout=timeout_ms)
        download = await download_info.value
        suggested = _safe_filename(download.suggested_filename)
        destination = DOWNLOAD_DIR / suggested
        await download.save_as(str(destination))
        return {
            "ok": True,
            "filename": suggested,
            "path": str(destination),
            "size_bytes": destination.stat().st_size,
        }


@mcp.tool()
async def browser_list_downloads() -> dict[str, Any]:
    """List files downloaded by this MCP browser server."""
    files = []
    for path in sorted(DOWNLOAD_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if path.is_file():
            stat = path.stat()
            files.append(
                {
                    "filename": path.name,
                    "size_bytes": stat.st_size,
                    "modified": stat.st_mtime,
                }
            )
    return {"directory": str(DOWNLOAD_DIR), "files": files[:200]}


@mcp.tool()
async def browser_read_download(
    filename: str,
    max_bytes: int = 2_000_000,
) -> dict[str, Any]:
    """Read a downloaded file as base64, restricted to the dedicated download folder."""
    safe = _safe_filename(filename)
    path = (DOWNLOAD_DIR / safe).resolve()
    if path.parent != DOWNLOAD_DIR:
        raise ValueError("Invalid filename")
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(safe)
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(
            f"File is {size} bytes, exceeding max_bytes={max_bytes}. "
            "Analyze it locally or request a smaller range in a future tool."
        )
    data = path.read_bytes()
    return {
        "filename": path.name,
        "size_bytes": size,
        "base64": base64.b64encode(data).decode("ascii"),
    }


@mcp.tool()
async def browser_tabs() -> dict[str, Any]:
    """List open tabs in the dedicated Chrome browser."""
    return await browser_status()


@mcp.tool()
async def browser_switch_tab(index: int) -> dict[str, Any]:
    """Switch the active controlled page to an open tab by index."""
    global _page
    async with _lock:
        await _ensure_page()
        assert _context is not None
        pages = [p for p in _context.pages if not p.is_closed()]
        if index < 0 or index >= len(pages):
            raise IndexError(f"Tab index {index} is out of range")
        _page = pages[index]
        _attach_network(_page)
        await _page.bring_to_front()
        return {
            "ok": True,
            "index": index,
            "url": _page.url,
            "title": await _page.title(),
        }


@mcp.tool()
async def browser_new_tab(url: str = "about:blank") -> dict[str, Any]:
    """Open and switch to a new browser tab."""
    global _page
    async with _lock:
        await _ensure_page()
        assert _context is not None
        _page = await _context.new_page()
        _attach_network(_page)
        if url != "about:blank":
            await _page.goto(url, wait_until="domcontentloaded")
        return {
            "ok": True,
            "url": _page.url,
            "title": await _page.title(),
        }


@mcp.tool()
async def browser_reload() -> dict[str, Any]:
    """Reload the current page."""
    async with _lock:
        page = await _ensure_page()
        await page.reload(wait_until="domcontentloaded")
        return {"ok": True, "url": page.url, "title": await page.title()}


@mcp.tool()
async def browser_back() -> dict[str, Any]:
    """Go back in browser history."""
    async with _lock:
        page = await _ensure_page()
        await page.go_back(wait_until="domcontentloaded")
        return {"ok": True, "url": page.url, "title": await page.title()}


@mcp.tool()
async def browser_forward() -> dict[str, Any]:
    """Go forward in browser history."""
    async with _lock:
        page = await _ensure_page()
        await page.go_forward(wait_until="domcontentloaded")
        return {"ok": True, "url": page.url, "title": await page.title()}


# ---------------------------------------------------------------------------
# Host file sharing tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def host_file_root() -> dict[str, Any]:
    """Show the filesystem root exposed by the host file tools."""
    return {
        "root": str(HOST_FILE_ROOT),
        "terminal_enabled": ALLOW_FULL_HOST_TERMINAL,
        "terminal_default_cwd": str(TERMINAL_DEFAULT_CWD),
        "terminal_shell": TERMINAL_SHELL,
    }


@mcp.tool()
async def host_list(
    path: str = ".",
    recursive: bool = False,
    max_entries: int = 500,
) -> dict[str, Any]:
    """List files under HOST_FILE_ROOT. Relative paths resolve from that root."""
    directory = _resolve_host_path(path, must_exist=True)
    if not directory.is_dir():
        raise NotADirectoryError(str(directory))

    max_entries = max(1, min(max_entries, 5000))
    iterator = directory.rglob("*") if recursive else directory.iterdir()
    entries: list[dict[str, Any]] = []
    errors: list[str] = []

    try:
        for item in iterator:
            try:
                stat = item.lstat()
                entries.append(
                    {
                        "name": item.name,
                        "path": str(item),
                        "relative_path": str(item.relative_to(HOST_FILE_ROOT)),
                        "type": (
                            "symlink"
                            if item.is_symlink()
                            else "directory"
                            if item.is_dir()
                            else "file"
                        ),
                        "size_bytes": stat.st_size if item.is_file() else None,
                        "modified": stat.st_mtime,
                    }
                )
            except OSError as exc:
                errors.append(f"{item}: {exc}")

            if len(entries) >= max_entries:
                break
    except OSError as exc:
        errors.append(str(exc))

    return {
        "root": str(HOST_FILE_ROOT),
        "path": str(directory),
        "recursive": recursive,
        "entries": entries,
        "errors": errors[:100],
        "truncated": len(entries) >= max_entries,
    }


@mcp.tool()
async def host_glob(
    pattern: str,
    path: str = ".",
    max_results: int = 500,
) -> dict[str, Any]:
    """Find host files matching a glob pattern under HOST_FILE_ROOT."""
    directory = _resolve_host_path(path, must_exist=True)
    if not directory.is_dir():
        raise NotADirectoryError(str(directory))

    max_results = max(1, min(max_results, 5000))
    results: list[dict[str, Any]] = []

    for item in directory.glob(pattern):
        try:
            item.resolve(strict=False).relative_to(HOST_FILE_ROOT)
        except ValueError:
            continue

        stat = item.lstat()
        results.append(
            {
                "path": str(item),
                "relative_path": str(item.relative_to(HOST_FILE_ROOT)),
                "type": (
                    "symlink"
                    if item.is_symlink()
                    else "directory"
                    if item.is_dir()
                    else "file"
                ),
                "size_bytes": stat.st_size if item.is_file() else None,
                "modified": stat.st_mtime,
            }
        )
        if len(results) >= max_results:
            break

    return {
        "root": str(HOST_FILE_ROOT),
        "pattern": pattern,
        "results": results,
        "truncated": len(results) >= max_results,
    }


@mcp.tool()
async def host_stat(path: str) -> dict[str, Any]:
    """Read metadata for a host file or directory."""
    target = _resolve_host_path(path, must_exist=True)
    stat = target.lstat()
    return {
        "path": str(target),
        "relative_path": str(target.relative_to(HOST_FILE_ROOT)),
        "type": (
            "symlink"
            if target.is_symlink()
            else "directory"
            if target.is_dir()
            else "file"
        ),
        "size_bytes": stat.st_size,
        "mode": oct(stat.st_mode & 0o7777),
        "modified": stat.st_mtime,
        "created": stat.st_ctime,
    }


@mcp.tool()
async def host_read_text(
    path: str,
    offset_chars: int = 0,
    max_chars: int = 200_000,
) -> dict[str, Any]:
    """Read a UTF-8 text slice from a host file."""
    target = _resolve_host_path(path, must_exist=True)
    if not target.is_file():
        raise FileNotFoundError(str(target))

    offset_chars = max(0, offset_chars)
    max_chars = max(1, min(max_chars, 1_000_000))
    content = target.read_text(encoding="utf-8", errors="replace")
    chunk = content[offset_chars : offset_chars + max_chars]

    return {
        "path": str(target),
        "offset_chars": offset_chars,
        "content": chunk,
        "next_offset_chars": offset_chars + len(chunk),
        "total_chars": len(content),
        "eof": offset_chars + len(chunk) >= len(content),
    }


@mcp.tool()
async def host_write_text(
    path: str,
    content: str,
    append: bool = False,
    create_parents: bool = True,
) -> dict[str, Any]:
    """Create, replace, or append to a UTF-8 host file."""
    target = _resolve_host_path(path)
    if create_parents:
        target.parent.mkdir(parents=True, exist_ok=True)

    mode = "a" if append else "w"
    with target.open(mode, encoding="utf-8") as handle:
        handle.write(content)

    return {
        "ok": True,
        "path": str(target),
        "append": append,
        "size_bytes": target.stat().st_size,
    }


@mcp.tool()
async def host_read_base64(
    path: str,
    offset_bytes: int = 0,
    length_bytes: int = 1_000_000,
) -> dict[str, Any]:
    """Read a binary host file in base64 chunks for transfer to ChatGPT."""
    target = _resolve_host_path(path, must_exist=True)
    if not target.is_file():
        raise FileNotFoundError(str(target))

    offset_bytes = max(0, offset_bytes)
    length_bytes = max(1, min(length_bytes, 5_000_000))
    total_size = target.stat().st_size

    with target.open("rb") as handle:
        handle.seek(offset_bytes)
        data = handle.read(length_bytes)

    return {
        "path": str(target),
        "offset_bytes": offset_bytes,
        "length_bytes": len(data),
        "next_offset_bytes": offset_bytes + len(data),
        "total_size_bytes": total_size,
        "eof": offset_bytes + len(data) >= total_size,
        "base64": base64.b64encode(data).decode("ascii"),
    }


@mcp.tool()
async def host_write_base64(
    path: str,
    base64_content: str,
    append: bool = False,
    create_parents: bool = True,
) -> dict[str, Any]:
    """Write a base64 chunk to a host file; use append=true for later chunks."""
    target = _resolve_host_path(path)
    if create_parents:
        target.parent.mkdir(parents=True, exist_ok=True)

    data = base64.b64decode(base64_content, validate=True)
    mode = "ab" if append else "wb"
    with target.open(mode) as handle:
        handle.write(data)

    return {
        "ok": True,
        "path": str(target),
        "append": append,
        "bytes_written": len(data),
        "size_bytes": target.stat().st_size,
    }


@mcp.tool()
async def host_sha256(path: str) -> dict[str, Any]:
    """Calculate the SHA-256 digest of a host file."""
    target = _resolve_host_path(path, must_exist=True)
    if not target.is_file():
        raise FileNotFoundError(str(target))

    digest = hashlib.sha256()
    with target.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)

    return {
        "path": str(target),
        "size_bytes": target.stat().st_size,
        "sha256": digest.hexdigest(),
    }


@mcp.tool()
async def host_mkdir(
    path: str,
    parents: bool = True,
    exist_ok: bool = True,
) -> dict[str, Any]:
    """Create a directory under HOST_FILE_ROOT."""
    target = _resolve_host_path(path)
    target.mkdir(parents=parents, exist_ok=exist_ok)
    return {"ok": True, "path": str(target)}


@mcp.tool()
async def host_copy(
    source: str,
    destination: str,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Copy a host file or directory under HOST_FILE_ROOT."""
    src = _resolve_host_path(source, must_exist=True)
    dst = _resolve_host_path(destination)

    if dst.exists() and not overwrite:
        raise FileExistsError(str(dst))
    dst.parent.mkdir(parents=True, exist_ok=True)

    if src.is_dir():
        shutil.copytree(src, dst, dirs_exist_ok=overwrite)
    else:
        shutil.copy2(src, dst)

    return {"ok": True, "source": str(src), "destination": str(dst)}


@mcp.tool()
async def host_move(
    source: str,
    destination: str,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Move or rename a host file or directory under HOST_FILE_ROOT."""
    src = _resolve_host_path(source, must_exist=True)
    dst = _resolve_host_path(destination)

    if dst.exists():
        if not overwrite:
            raise FileExistsError(str(dst))
        if dst.is_dir() and not dst.is_symlink():
            shutil.rmtree(dst)
        else:
            dst.unlink()

    dst.parent.mkdir(parents=True, exist_ok=True)
    result = shutil.move(str(src), str(dst))
    return {"ok": True, "source": str(src), "destination": result}


@mcp.tool()
async def host_delete(
    path: str,
    recursive: bool = False,
) -> dict[str, Any]:
    """Delete a host file or directory under HOST_FILE_ROOT."""
    target = _resolve_host_path(path, must_exist=True)
    if target == HOST_FILE_ROOT:
        raise PermissionError("Refusing to delete HOST_FILE_ROOT itself")

    if target.is_dir() and not target.is_symlink():
        if recursive:
            shutil.rmtree(target)
        else:
            target.rmdir()
    else:
        target.unlink()

    return {"ok": True, "deleted": str(target)}


@mcp.tool()
async def host_chmod(path: str, mode: str) -> dict[str, Any]:
    """Change host file permissions using an octal mode such as 755 or 0644."""
    target = _resolve_host_path(path, must_exist=True)
    normalized = mode.strip().lower().removeprefix("0o")
    numeric_mode = int(normalized, 8)
    target.chmod(numeric_mode)
    return {
        "ok": True,
        "path": str(target),
        "mode": oct(target.stat().st_mode & 0o7777),
    }


# ---------------------------------------------------------------------------
# Full host terminal tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def terminal_status() -> dict[str, Any]:
    """Show whether full host terminal access is enabled."""
    return {
        "enabled": ALLOW_FULL_HOST_TERMINAL,
        "shell": TERMINAL_SHELL,
        "default_cwd": str(TERMINAL_DEFAULT_CWD),
        "warning": (
            "When enabled, terminal tools have the same user-level access as "
            "the account running tunnel-client."
        ),
    }


@mcp.tool()
async def terminal_exec(
    command: str,
    cwd: str = "",
    timeout_seconds: int = 120,
    max_output_chars: int = 200_000,
    extra_env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Run an arbitrary one-shot command through the host zsh shell.

    This is full user-level terminal access to the Mac. Runtime connector
    credentials are removed from the child environment by default.
    """
    _terminal_enabled()

    if not command.strip():
        raise ValueError("command cannot be empty")

    working_directory = _resolve_terminal_cwd(cwd)
    timeout_seconds = max(1, min(timeout_seconds, 3600))
    max_output_chars = max(1, min(max_output_chars, 1_000_000))

    process = await asyncio.create_subprocess_exec(
        TERMINAL_SHELL,
        "-lc",
        command,
        cwd=str(working_directory),
        env=_terminal_environment(extra_env),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )

    timed_out = False
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout_seconds,
        )
    except asyncio.TimeoutError:
        timed_out = True
        await _terminate_process_group(process, signal.SIGTERM)
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=3,
            )
        except asyncio.TimeoutError:
            await _terminate_process_group(process, signal.SIGKILL)
            stdout, stderr = await process.communicate()

    stdout_text, stdout_truncated = _decode_output(
        stdout, max_output_chars
    )
    stderr_text, stderr_truncated = _decode_output(
        stderr, max_output_chars
    )

    return {
        "ok": process.returncode == 0 and not timed_out,
        "command": command,
        "cwd": str(working_directory),
        "pid": process.pid,
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
    }


@mcp.tool()
async def terminal_start(
    initial_command: str = "",
    cwd: str = "",
    extra_env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Start a persistent interactive zsh session on the host Mac.

    Use terminal_write, terminal_read, terminal_signal, and terminal_close with
    the returned session_id.
    """
    _terminal_enabled()
    working_directory = _resolve_terminal_cwd(cwd)
    session_id = secrets.token_hex(12)

    process = await asyncio.create_subprocess_exec(
        TERMINAL_SHELL,
        "-i",
        cwd=str(working_directory),
        env=_terminal_environment(extra_env),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        start_new_session=True,
    )

    session: dict[str, Any] = {
        "process": process,
        "cwd": str(working_directory),
        "started_at": time.time(),
        "finished_at": None,
        "exit_code": None,
        "initial_command": initial_command,
        "buffer": bytearray(),
        "read_offset": 0,
        "buffer_lock": asyncio.Lock(),
    }

    async with _terminal_sessions_lock:
        _terminal_sessions[session_id] = session

    session["pump_task"] = asyncio.create_task(
        _terminal_output_pump(session_id)
    )

    if initial_command.strip():
        assert process.stdin is not None
        process.stdin.write((initial_command + "\n").encode("utf-8"))
        await process.stdin.drain()

    return _terminal_session_snapshot(session_id, session)


@mcp.tool()
async def terminal_write(
    session_id: str,
    data: str,
    append_newline: bool = False,
) -> dict[str, Any]:
    """Write text or a command to a persistent terminal session."""
    _terminal_enabled()
    session = _terminal_sessions.get(session_id)
    if not session:
        raise KeyError(f"Unknown terminal session: {session_id}")

    process: asyncio.subprocess.Process = session["process"]
    if process.returncode is not None or process.stdin is None:
        raise RuntimeError("Terminal session is no longer running")

    payload = data + ("\n" if append_newline else "")
    process.stdin.write(payload.encode("utf-8"))
    await process.stdin.drain()

    return {
        "ok": True,
        "session_id": session_id,
        "bytes_written": len(payload.encode("utf-8")),
    }


@mcp.tool()
async def terminal_read(
    session_id: str,
    wait_ms: int = 250,
    max_chars: int = 200_000,
) -> dict[str, Any]:
    """Read new output from a persistent terminal session."""
    _terminal_enabled()
    session = _terminal_sessions.get(session_id)
    if not session:
        raise KeyError(f"Unknown terminal session: {session_id}")

    wait_ms = max(0, min(wait_ms, 30_000))
    max_chars = max(1, min(max_chars, 1_000_000))

    deadline = time.monotonic() + (wait_ms / 1000)
    while True:
        async with session["buffer_lock"]:
            if session["read_offset"] < len(session["buffer"]):
                break
        process: asyncio.subprocess.Process = session["process"]
        if process.returncode is not None or time.monotonic() >= deadline:
            break
        await asyncio.sleep(0.05)

    async with session["buffer_lock"]:
        buffer: bytearray = session["buffer"]
        start = session["read_offset"]
        raw = bytes(buffer[start:])
        text = raw.decode("utf-8", errors="replace")
        chunk = text[:max_chars]
        consumed_bytes = len(chunk.encode("utf-8", errors="replace"))
        session["read_offset"] = min(len(buffer), start + consumed_bytes)

    snapshot = _terminal_session_snapshot(session_id, session)
    snapshot.update(
        {
            "output": chunk,
            "output_truncated": len(text) > max_chars,
            "unread_bytes_remaining": max(
                0, len(session["buffer"]) - session["read_offset"]
            ),
        }
    )
    return snapshot


@mcp.tool()
async def terminal_signal(
    session_id: str,
    signal_name: str = "SIGINT",
) -> dict[str, Any]:
    """Send SIGINT, SIGTERM, SIGHUP, SIGQUIT, or SIGKILL to a terminal session."""
    _terminal_enabled()
    session = _terminal_sessions.get(session_id)
    if not session:
        raise KeyError(f"Unknown terminal session: {session_id}")

    allowed = {
        "SIGINT": signal.SIGINT,
        "SIGTERM": signal.SIGTERM,
        "SIGHUP": signal.SIGHUP,
        "SIGQUIT": signal.SIGQUIT,
        "SIGKILL": signal.SIGKILL,
    }
    normalized = signal_name.strip().upper()
    if normalized not in allowed:
        raise ValueError(f"signal_name must be one of {sorted(allowed)}")

    process: asyncio.subprocess.Process = session["process"]
    await _terminate_process_group(process, allowed[normalized])
    return {
        "ok": True,
        "session_id": session_id,
        "signal": normalized,
    }


@mcp.tool()
async def terminal_close(
    session_id: str,
    force: bool = False,
) -> dict[str, Any]:
    """Close and remove a persistent terminal session."""
    _terminal_enabled()
    session = _terminal_sessions.get(session_id)
    if not session:
        raise KeyError(f"Unknown terminal session: {session_id}")

    process: asyncio.subprocess.Process = session["process"]
    if process.returncode is None:
        await _terminate_process_group(
            process,
            signal.SIGKILL if force else signal.SIGTERM,
        )
        try:
            await asyncio.wait_for(process.wait(), timeout=3)
        except asyncio.TimeoutError:
            await _terminate_process_group(process, signal.SIGKILL)
            await process.wait()

    task = session.get("pump_task")
    if task is not None:
        try:
            await task
        except asyncio.CancelledError:
            pass

    snapshot = _terminal_session_snapshot(session_id, session)
    async with _terminal_sessions_lock:
        _terminal_sessions.pop(session_id, None)
    snapshot["removed"] = True
    return snapshot


@mcp.tool()
async def terminal_list_sessions() -> dict[str, Any]:
    """List persistent terminal sessions created by this MCP server."""
    _terminal_enabled()
    async with _terminal_sessions_lock:
        sessions = [
            _terminal_session_snapshot(session_id, session)
            for session_id, session in _terminal_sessions.items()
        ]
    return {"sessions": sessions}


if __name__ == "__main__":
    mcp.run(transport="stdio")