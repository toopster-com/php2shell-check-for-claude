# php2shell-check (plugin)

Passive check whether a website or server runs a PHP version affected by PHP2Shell (CVE-2026-109618 and CVE-2026-109619). The skill reads the PHP version from the response headers of a website, from `php -v` on the local machine or from a version you type in, and compares it with the first fixed release of its branch (8.5.12, 8.4.27, 8.3.36, 8.2.35). It never sends exploit requests. UNKNOWN does not mean safe.

Install in Claude Code:

```
/plugin marketplace add toopster-com/php2shell-check
/plugin install php2shell-check@toopster
```

Full documentation, limits and sources: see the README at the repository root, https://github.com/toopster-com/php2shell-check
