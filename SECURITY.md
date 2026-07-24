# Security

This server exposes terminal, filesystem, browser, and desktop-control tools
from the Mac account that runs it. Treat access to the MCP app as equivalent
to remote access to that macOS user.

## Safe operation

- Use a dedicated ChatGPT workspace or account.
- Keep the tunnel runtime key in a mode-`600` file outside the repository.
- Never commit `.env`, key files, tunnel credentials, browser profiles, or
  session journals.
- Review and enable only the MCP actions you intend to expose.
- Stop the runtime with `codex-mcp stop` when it is not needed.
- Use a dedicated macOS account or VM if you need stronger isolation.
- Rotate a key immediately if it appears in a terminal transcript, log,
  screenshot, commit, or shared file.

## Reporting

Open a GitHub security advisory rather than a public issue for vulnerabilities
that could expose credentials or enable unintended host access.
