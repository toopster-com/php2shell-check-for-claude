# php2shell-check for Claude

A passive check for Claude whether a website or server runs a PHP version affected by **PHP2Shell** (CVE-2026-109618 and CVE-2026-109619). Works as a Claude Code plugin, as a skill on claude.ai and as a plain command line tool.

[Deutsch weiter unten](#auf-deutsch)

## What it does

PHP2Shell is the name security researchers use for two critical remote code execution flaws in PHP (CVSS v4.0 9.2). The PHP project published fixed releases on 21 October 2026. This tool reads the PHP version of a website, of the local machine or a version you type in, and compares it with the first fixed release of its branch:

- PHP 8.5: 8.5.12
- PHP 8.4: 8.4.27
- PHP 8.3: 8.3.36
- PHP 8.2: 8.2.35 (security support for 8.2 ends on 31 December 2026)
- PHP 8.1 and older: no official release with the fix

It is passive. For a website it sends one HEAD request (a GET only if the server answers HEAD with 405 or 501), follows no redirects, reads no response body and only looks at the `X-Powered-By` and `Server` headers. It never sends exploit requests and does not test the flaw itself.

Results:

- **PATCHED** (exit code 0): at or above the first fixed release. A version comparison, not proof.
- **AFFECTED** (exit code 1): below the fix. Update now.
- **UNSUPPORTED** (exit code 1): PHP 8.1 or older. No official fix, treat as affected and upgrade.
- **UNKNOWN** (exit code 3): no version visible, a redirect, a vendor build, a pre-release or no answer. **UNKNOWN does not mean safe.**

## Install

### Claude Code

```
/plugin marketplace add toopster-com/php2shell-check-for-claude
/plugin install php2shell-check@toopster
```

Or from a terminal:

```
claude plugin marketplace add toopster-com/php2shell-check-for-claude
claude plugin install php2shell-check@toopster
```

Then ask Claude, for example: "Is https://example.com affected by PHP2Shell?" or "Check the PHP version on this server for PHP2Shell."

### claude.ai

Download `php2shell-check.zip` from the [latest release](https://github.com/toopster-com/php2shell-check-for-claude/releases/latest) and upload it under Customize > Skills > "+" > "+ Create skill" > "Upload a skill". Code execution must be switched on in your settings. The code environment on claude.ai usually cannot reach arbitrary websites, so on claude.ai the skill mostly works with a version number you give it (for example from your hosting panel).

### Command line, without Claude

Needs Node.js 20 or newer (tested on 20, 22 and 24), no other dependencies:

```
node plugins/php2shell-check/skills/php2shell-check/scripts/php2shell-check.mjs --url https://example.com
node plugins/php2shell-check/skills/php2shell-check/scripts/php2shell-check.mjs --local
node plugins/php2shell-check/skills/php2shell-check/scripts/php2shell-check.mjs --version 8.3.30
```

Add `--json` for machine-readable output.

## Limits

- Many servers hide the PHP version, and headers can be changed. A CDN or proxy can hide PHP completely.
- Distributions such as Debian and Ubuntu backport fixes without raising the PHP version number. Such builds come out as UNKNOWN, with links to the security trackers. Red Hat style builds keep the plain upstream number and may come out as AFFECTED although the vendor has patched them. Then the vendor's advisory decides.
- The command line `php` can differ from the PHP that serves your website (often `php-fpm`).
- The version list reflects the PHP advisory of 21 October 2026. We update it if PHP publishes further fixes.

## Use it responsibly

Check only systems you are responsible for or have permission to check. The skill tells Claude to decline bulk checks of other people's sites.

Found a security problem in this tool? Please report it privately, see [SECURITY.md](SECURITY.md).

## Tests

```
node --test tests/*.test.mjs
```

The tests run against local HTTP servers on 127.0.0.1 and never start a real PHP binary.

## Why this exists

We are building toopster, a platform for construction tenders, with Claude Code. While working on it we followed the PHP2Shell news of 21 October 2026. OpenAI had published a checker for Codex users, and we noticed that we, as Claude users, had nothing comparable. So we checked our own site by hand (toopster runs no PHP and is not affected), wrote this skill, and are sharing it with everyone who works with Claude.

## Sources and credits

- PHP security advisory of 21 October 2026: https://www.php.net/archive/2026.php#2026-10-21-5
- GitHub security advisories of the PHP project: [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) (CVE-2026-109618) and [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) (CVE-2026-109619)
- Inspired by [openai/php2shell-checker](https://github.com/openai/php2shell-checker) (Apache-2.0). This is an independent implementation; no code from that project is included.

Not affiliated with Anthropic, OpenAI or the PHP project.

## License

Apache License 2.0, see [LICENSE](LICENSE). Provided without warranty.

## About toopster

toopster is a platform for construction tenders in Germany. Builders publish a tender with a bill of quantities, and contractors submit sealed offers that no other contractor can see. [toopster.com](https://toopster.com)

---

## Auf Deutsch

**Was es ist:** Ein passiver Prüfer für Claude, ob eine Website oder ein Server eine PHP-Version nutzt, die von **PHP2Shell** (CVE-2026-109618 und CVE-2026-109619) betroffen ist. Er liest nur die PHP-Version (Kopfzeilen der Website oder `php -v` auf dem Server) und vergleicht sie mit der ersten reparierten Version: 8.5.12, 8.4.27, 8.3.36 und 8.2.35. Für PHP 8.1 und älter gibt es keine offizielle Version mit dem Fix. Er greift nichts an und testet die Lücke nicht.

**Ergebnisse:** PATCHED (repariert), AFFECTED (betroffen, sofort aktualisieren), UNSUPPORTED (8.1 oder älter, ohne offiziellen Fix, umsteigen) und UNKNOWN (unklar). **Unklar heißt nicht sicher.**

**Installation in Claude Code:**

```
/plugin marketplace add toopster-com/php2shell-check-for-claude
/plugin install php2shell-check@toopster
```

Danach Claude einfach fragen, etwa: „Ist https://example.com von PHP2Shell betroffen?“ Für claude.ai die Datei `php2shell-check.zip` aus dem [neuesten Release](https://github.com/toopster-com/php2shell-check-for-claude/releases/latest) unter Customize > Skills über „+“, „Create skill“ und „Upload a skill“ hochladen.

**Bitte nur eigene Systeme prüfen** oder solche, für die eine Erlaubnis vorliegt.

**Warum es das gibt:** Wir entwickeln toopster, eine Plattform für Ausschreibungen am Bau, mit Claude Code. Dabei haben wir die Meldungen zu PHP2Shell vom 21. Oktober 2026 verfolgt. OpenAI hatte für Codex einen Prüfer veröffentlicht, und uns fiel auf, dass wir als Claude-Nutzer nichts Vergleichbares hatten. Also haben wir unsere eigene Seite von Hand geprüft (toopster nutzt kein PHP und ist nicht betroffen), diesen Skill geschrieben und teilen ihn mit allen, die mit Claude arbeiten.

**Über toopster:** toopster ist eine Plattform für Ausschreibungen am Bau in Deutschland. Bauherren schreiben mit Leistungsverzeichnis aus, und Betriebe geben verdeckte Angebote ab, die kein anderer Betrieb sieht. [toopster.com](https://toopster.com)

Lizenz Apache 2.0, ohne Gewähr. Kein Angebot von Anthropic, OpenAI oder dem PHP-Projekt.

---

toopster UG (haftungsbeschränkt) · [Impressum](https://toopster.com/impressum)
