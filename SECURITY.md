# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous releases | Best effort |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **roland@mystier.li**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 1 week
- **Fix timeline:** Depends on severity

## Scope

This security policy covers the MCP server code in this repository. It does NOT cover:
- FortiAnalyzer itself (report to [Fortinet PSIRT](https://www.fortiguard.com/psirt))
- The MCP protocol (report to the MCP specification maintainers)
- Third-party dependencies (report to their respective maintainers)

## Security Best Practices

When using this MCP server:
- Use API tokens with minimum required permissions
- Store credentials in environment variables, never in code
- Use `ALLOWED_OUTPUT_DIRS` to restrict file output locations
- Run in Docker for additional isolation
