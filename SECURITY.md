# Security policy

## Reporting a vulnerability

Please report security problems in this plugin privately through GitHub: open the [Security tab](https://github.com/toopster-com/php2shell-check-for-claude/security) of this repository and choose "Report a vulnerability". Please do not open a public issue for a vulnerability.

We aim to reply within 7 days, investigate every report and tell you what we will do about it. Fixes are released as a new version of the plugin.

## Scope

This repository contains a passive version checker. It sends one HEAD request (or a GET if the server answers HEAD with 405 or 501) to the address the user names, and it runs `php -v` and similar commands on the local machine. Reports about wrong results, for example a version shown as patched that is not, are welcome too: privately as above, or as a normal issue if the details are not sensitive.

Questions about the PHP2Shell flaws themselves (CVE-2026-109618, CVE-2026-109619) belong to the PHP project: https://github.com/php/php-src/security
