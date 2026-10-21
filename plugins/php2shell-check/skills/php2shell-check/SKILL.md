---
name: php2shell-check
description: Checks passively whether a website or server runs a PHP version affected by PHP2Shell (CVE-2026-109618, CVE-2026-109619). Use when asked if a site or PHP install needs the update.
license: Apache-2.0
compatibility: Needs Node.js 20 or newer. Website checks need network access to the site.
metadata:
  version: "1.0.0"
  source: "https://github.com/toopster-com/php2shell-check"
---

# PHP2Shell check

PHP2Shell is the name used by security researchers for two critical remote code execution flaws in PHP, CVE-2026-109618 and CVE-2026-109619 (CVSS v4.0 9.2). The PHP project fixed them on 21 October 2026. This skill finds out which PHP version a website or server runs and compares it with the first fixed release of its branch. It only reads version information. It never sends exploit requests and never tests the flaw itself.

## Rules

- Check only systems the user is responsible for or has permission to check. If the user asks to check sites of others in bulk, or wants a list of vulnerable sites, decline that part and offer to check their own systems instead.
- One target per run. Do not loop over lists of third-party domains.
- Stay passive: no extra requests, no payloads, no guessing of paths. The script sends one HEAD request (a GET only if the server answers HEAD with 405 or 501), follows no redirects and reads no response body.
- UNKNOWN never means safe. Say so whenever the result is UNKNOWN.

## Steps

1. **Pick the mode.**
   - The user names a website: `--url https://example.com`
   - The user asks about the machine Claude runs on, or a server where Claude has a shell: `--local` (runs `php -v`, `php-fpm -v`, `php-cgi -v` and versioned binaries such as `php8.3`)
   - The user already knows the version, for example from the hosting panel: `--version 8.3.30`
2. **Run the script** that comes with this skill:
   ```
   node "${CLAUDE_SKILL_DIR}/scripts/php2shell-check.mjs" --url https://example.com
   ```
   Add `--json` when you want to parse the result. If `${CLAUDE_SKILL_DIR}` was not replaced by a path (for example on claude.ai), the script is `scripts/php2shell-check.mjs` inside this skill's folder.
   Exit codes: 0 patched, 1 affected or unsupported, 2 usage error, 3 unknown.
3. **If Node.js is missing**, do the same by hand and compare with the table below: `curl -sSI --max-redirs 0 https://example.com` and read the `X-Powered-By` and `Server` headers (only the response headers, no body), or run `php -v` on the server.
4. **Explain the result** in the user's language, in plain words, with the concrete next step:
   - **PATCHED:** The version is at or above the first fixed release. This is a version comparison, not proof. Keep updates switched on.
   - **AFFECTED:** Update to the fixed release of that branch (table below) as soon as possible. On shared hosting this is often a PHP version switch in the hosting panel or a request to the host.
   - **UNSUPPORTED (PHP 8.1 and older):** There is no official release with the fix. Treat the system as affected and plan the upgrade to PHP 8.4 or 8.5, at the very least to PHP 8.2.35.
   - **UNKNOWN:** Say why (version hidden, redirect, vendor build, pre-release, unknown branch, no answer) and how to get a clear answer: run `--local` on the server, look up the PHP version in the hosting panel, or check the distribution's security tracker that the script lists. On a redirect, check the target address too, if it also belongs to the user.
5. **Name the limits** that apply to this case (see below) and give the source: https://www.php.net/archive/2026.php#2026-10-21-5

## First fixed releases (PHP advisory of 21 October 2026)

- PHP 8.5: 8.5.12
- PHP 8.4: 8.4.27
- PHP 8.3: 8.3.36
- PHP 8.2: 8.2.35 (security support for 8.2 ends on 31 December 2026)
- PHP 8.1 and older: no official release with the fix. The PHP project published source patches for 7.4, 8.0 and 8.1, and some distributions ship backports.
- PHP 8.6 is still in pre-release. Pre-releases do not belong in production.

## Limits

- Many servers hide the PHP version, and headers can be changed. A CDN or proxy in front of the site can hide PHP completely.
- Vendor builds: Debian, Ubuntu and others backport fixes without raising the PHP version number. The script reports such builds as UNKNOWN and lists the trackers. Red Hat style builds keep the plain upstream number, so the script may report AFFECTED although the vendor has patched it. Then the vendor's advisory decides.
- The command line `php` can differ from the PHP that serves the website (often `php-fpm`, or several versions side by side). `--local` lists every binary it finds.
- The version list reflects the advisory of 21 October 2026. If PHP publishes further fixes, the list in the script must be updated.

## Sources

- PHP advisory: https://www.php.net/archive/2026.php#2026-10-21-5
- GitHub advisories: https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w and https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
