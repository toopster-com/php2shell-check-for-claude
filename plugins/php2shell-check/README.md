# php2shell-check (plugin)

Passive check whether a website or server runs a PHP version affected by PHP2Shell (CVE-2026-109618 and CVE-2026-109619). The skill reads the PHP version from the response headers of a website, from `php -v` on the local machine or from a version you type in, and compares it with the first fixed release of its branch (8.5.12, 8.4.27, 8.3.36, 8.2.35). It never sends exploit requests. UNKNOWN does not mean safe.

Check only systems you are responsible for or have permission to check.

## What it runs, sends and stores

- Website check (`--url`): one HEAD request to the address you name, or a GET if the server answers HEAD with 405 or 501. It follows no redirects, reads only the `X-Powered-By`, `Server` and `Location` response headers and never reads the response body.
- Local check (`--local`): runs `php -v` and the same for `php-fpm`, `php-cgi` and versioned binaries such as `php8.3` on the machine Claude runs on.
- Version check (`--version`): no network access and no commands.
- Nothing is sent to toopster or anyone else. No telemetry, nothing is stored or written to disk.
- The script is plain, readable JavaScript for Node.js 20 or newer, with no dependencies and no downloads.

## Examples

- "Is https://example.com affected by PHP2Shell?"
- "Check the PHP version on this server for PHP2Shell."
- "My hosting panel says PHP 8.3.30. Do I need to update because of PHP2Shell?"

## Privacy

The plugin collects, stores and sends no personal data and has no server of its own. The only network request goes to the website you name, as described above.

## Support and security reports

Questions and wrong results: [GitHub Issues](https://github.com/toopster-com/php2shell-check-for-claude/issues). Security problems: privately through "Report a vulnerability" in the [Security tab](https://github.com/toopster-com/php2shell-check-for-claude/security), see [SECURITY.md](https://github.com/toopster-com/php2shell-check-for-claude/blob/main/SECURITY.md).

## Install in Claude Code

```
/plugin marketplace add toopster-com/php2shell-check-for-claude
/plugin install php2shell-check@toopster
```

Full documentation, limits and sources: see the README at the repository root, https://github.com/toopster-com/php2shell-check-for-claude
