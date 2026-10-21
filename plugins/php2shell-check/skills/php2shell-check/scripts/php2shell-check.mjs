#!/usr/bin/env node
// Copyright 2026 toopster UG (haftungsbeschränkt). Licensed under the Apache License, Version 2.0 (see LICENSE).
// php2shell-check: passive check for PHP2Shell (CVE-2026-109618, CVE-2026-109619).
//
// Reads the PHP version from a website's HTTP response headers (X-Powered-By, Server), from local PHP binaries
// (`php -v`, `php-fpm -v`, `php-cgi -v`) or from a version number the user provides, and compares it with the first fixed
// release per branch from the PHP security advisory of 21 October 2026. It sends no exploit requests: one HEAD request per
// URL (GET only if the server answers HEAD with 405 or 501), no redirects followed, no response body read.
//
// Source: https://www.php.net/archive/2026.php#2026-10-21-5
// No dependencies; Node.js 20 or newer (tested on 20, 22 and 24).

import { spawnSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'

export const ADVISORY = Object.freeze({
  name: 'PHP2Shell',
  cves: Object.freeze(['CVE-2026-109618', 'CVE-2026-109619']),
  published: '2026-10-21',
  url: 'https://www.php.net/archive/2026.php#2026-10-21-5',
  // First fixed patch release of each supported branch (php.net, 21 October 2026).
  fixed: Object.freeze({ '8.2': 35, '8.3': 36, '8.4': 27, '8.5': 12 }),
})

export const STATUS = Object.freeze({
  PATCHED: 'patched',
  AFFECTED: 'affected',
  UNSUPPORTED: 'unsupported',
  UNKNOWN: 'unknown',
})

// 0 patched, 1 affected or unsupported, 2 usage error, 3 unknown.
const EXIT_CODE = Object.freeze({ patched: 0, affected: 1, unsupported: 1, unknown: 3 })
const SEVERITY = Object.freeze({ affected: 3, unsupported: 2, unknown: 1, patched: 0 })

const DISTRO_TRACKERS = Object.freeze([
  'Debian: https://security-tracker.debian.org/tracker/CVE-2026-109618',
  'Ubuntu: https://ubuntu.com/security/CVE-2026-109618',
  'Red Hat and derivatives: https://access.redhat.com/security/cve/CVE-2026-109618',
])

/** Parses "8.3.12", "8.2.7-1~deb12u1" or "8.6.0RC4" into its parts, or returns null. */
export function parseVersion(text) {
  if (typeof text !== 'string') return null
  const m = text.trim().match(/^(\d+)\.(\d+)\.(\d+)(\S*)$/)
  if (!m) return null
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]), suffix: m[4], raw: m[0] }
}

/** Finds a PHP version in header values such as "PHP/8.3.12" or "Apache/2.4.62 (Debian) PHP/8.2.7". */
export function versionFromHeaders(headers) {
  for (const value of [headers.poweredBy, headers.server]) {
    if (!value) continue
    const m = String(value).match(/PHP\/(\d+\.\d+\.\d+[^\s,;]*)/i)
    if (m) return m[1]
  }
  return null
}

/** Finds the version in the first line of `php -v` output, e.g. "PHP 8.4.26 (cli) (built: ...)". */
export function versionFromCli(output) {
  const m = String(output ?? '').match(/^PHP (\d+\.\d+\.\d+\S*)/m)
  return m ? m[1] : null
}

function isPrerelease(suffix) {
  return /^[-.~]?(alpha|beta|rc|dev)/i.test(suffix)
}

// Upstream PHP versions have no suffix. A suffix such as "-1~deb12u1", "-1ubuntu2.20", "-1.amzn2023" or "-150500.1.1"
// marks a vendor build, and vendors often backport security fixes without raising the upstream patch number, so a
// lower number alone does not prove the build is affected. (Red Hat style builds keep the plain upstream number and
// cannot be recognised this way; the documentation says so.)
function isVendorBuild(suffix) {
  return suffix !== '' && !isPrerelease(suffix)
}

const TRACKER_HINT = `check your distribution's security tracker for ${ADVISORY.cves.join(' and ')}. Until it shows a fixed package that you have installed, treat the system as affected.`

/** Compares one version string with the advisory. Pure function. */
export function evaluate(versionText) {
  const v = parseVersion(versionText)
  if (!v) {
    return {
      status: STATUS.UNKNOWN,
      version: versionText ?? null,
      reason: 'No PHP version found. This does not mean the system is safe: many servers hide the version.',
    }
  }
  const branch = `${v.major}.${v.minor}`
  if (v.major < 8 || (v.major === 8 && v.minor <= 1)) {
    if (isVendorBuild(v.suffix)) {
      return {
        status: STATUS.UNKNOWN,
        version: v.raw,
        reason: `PHP ${v.raw} is a vendor build of PHP ${branch}, a branch without an official release with the fix. Some distributions backport the fixes (the PHP project published source patches for 7.4, 8.0 and 8.1), so ${TRACKER_HINT} Upgrading to a supported branch is the safer path.`,
        trackers: DISTRO_TRACKERS,
      }
    }
    return {
      status: STATUS.UNSUPPORTED,
      version: v.raw,
      reason: `PHP ${branch} gets no official release with the fix (the PHP project published source patches for 7.4, 8.0 and 8.1, nothing for older branches). Treat this system as affected and upgrade to a supported branch: PHP 8.4 or 8.5, at the very least PHP 8.2.35.`,
    }
  }
  const fixedPatch = ADVISORY.fixed[branch]
  if (fixedPatch === undefined) {
    return {
      status: STATUS.UNKNOWN,
      version: v.raw,
      reason: `PHP ${branch} is newer than the branches this tool knows (8.2 to 8.5). Check ${ADVISORY.url} for the current list.`,
    }
  }
  if (isPrerelease(v.suffix)) {
    return {
      status: STATUS.UNKNOWN,
      version: v.raw,
      reason: `PHP ${v.raw} is a pre-release and not meant for production. Use a stable release, at least PHP ${branch}.${fixedPatch}.`,
    }
  }
  if (v.patch >= fixedPatch) {
    return {
      status: STATUS.PATCHED,
      version: v.raw,
      reason: `PHP ${v.raw} is at or above PHP ${branch}.${fixedPatch}, the first release with the fix. This is a version comparison, not a test of the fix itself.`,
    }
  }
  if (isVendorBuild(v.suffix)) {
    return {
      status: STATUS.UNKNOWN,
      version: v.raw,
      reason: `PHP ${v.raw} looks like a vendor build below PHP ${branch}.${fixedPatch}. Distributions often add security fixes without changing the PHP version number, so ${TRACKER_HINT}`,
      trackers: DISTRO_TRACKERS,
    }
  }
  return {
    status: STATUS.AFFECTED,
    version: v.raw,
    reason: `PHP ${v.raw} is below PHP ${branch}.${fixedPatch}, the first release with the fix. Update to PHP ${branch}.${fixedPatch} or newer as soon as possible.`,
  }
}

/** Worst status of several findings (affected > unsupported > unknown > patched). */
export function worstStatus(findings) {
  if (findings.length === 0) return STATUS.UNKNOWN
  return findings.reduce((worst, f) => (SEVERITY[f.status] > SEVERITY[worst] ? f.status : worst), STATUS.PATCHED)
}

/** Checks one website by its response headers. One HEAD request (GET only on 405 or 501), no redirects, no body. */
export async function checkUrl(target, { timeoutMs = 10_000, fetchImpl = globalThis.fetch } = {}) {
  let url
  try {
    url = new URL(target)
  } catch {
    throw new UsageError(`Not a valid URL: ${target}`)
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new UsageError('Only http and https URLs can be checked.')

  const request = async (method) => {
    const res = await fetchImpl(url.href, { method, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) })
    // Never read the body; release the connection instead.
    try { await res.body?.cancel() } catch { /* nothing to release */ }
    return res
  }

  let res
  try {
    res = await request('HEAD')
    if (res.status === 405 || res.status === 501) res = await request('GET')
  } catch (error) {
    return {
      target: url.href,
      httpStatus: null,
      headers: {},
      ...evaluate(null),
      reason: `The website did not answer (${error?.name === 'TimeoutError' ? 'timeout' : 'network error'}). No result: this does not mean the site is safe.`,
    }
  }

  const headers = { poweredBy: res.headers.get('x-powered-by'), server: res.headers.get('server') }
  const finding = { target: url.href, httpStatus: res.status, headers, ...evaluate(versionFromHeaders(headers)) }
  const location = res.headers.get('location')
  if (res.status >= 300 && res.status < 400 && location) {
    finding.redirect = new URL(location, url).href
    if (finding.status === STATUS.UNKNOWN) {
      finding.reason += ` The address redirects to ${finding.redirect}; run the check on that address too.`
    }
  }
  return finding
}

const LOCAL_BINARIES = Object.freeze([
  'php', 'php-fpm', 'php-cgi',
  'php8.5', 'php8.4', 'php8.3', 'php8.2', 'php8.1', 'php8.0', 'php7.4',
  'php-fpm8.5', 'php-fpm8.4', 'php-fpm8.3', 'php-fpm8.2', 'php-fpm8.1', 'php-fpm8.0', 'php-fpm7.4',
])

/** Runs `<binary> -v` for the usual PHP binaries on this machine. */
export function checkLocal({ run = spawnSync, binaries = LOCAL_BINARIES } = {}) {
  const findings = []
  for (const binary of binaries) {
    let result
    try {
      result = run(binary, ['-v'], { encoding: 'utf8', timeout: 5_000 })
    } catch {
      continue
    }
    if (!result || result.error || result.status !== 0) continue
    const version = versionFromCli(result.stdout)
    if (!version) continue
    findings.push({ target: binary, ...evaluate(version) })
  }
  return findings
}

export class UsageError extends Error {}

const USAGE = `php2shell-check: passive check for PHP2Shell (${ADVISORY.cves.join(', ')})

Usage:
  node php2shell-check.mjs --url https://example.com [--json]
  node php2shell-check.mjs --local [--json]
  node php2shell-check.mjs --version 8.3.30 [--json]

  --url       Read the PHP version from the response headers of one website you are responsible for.
  --local     Run "php -v" (and php-fpm, php-cgi) on this machine.
  --version   Evaluate a version number you read elsewhere, for example in your hosting panel.
  --json      Machine-readable output.

Exit codes: 0 patched, 1 affected or unsupported, 2 usage error, 3 unknown.
Source: ${ADVISORY.url}`

export function parseArgs(argv) {
  const args = { json: false }
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i]
    if (a === '--json') args.json = true
    else if (a === '--local') {
      if (args.mode) throw new UsageError('Use exactly one of --url, --local or --version.')
      args.mode = 'local'
    }
    else if (a === '--url' || a === '--version') {
      const value = argv[i + 1]
      if (!value || value.startsWith('--')) throw new UsageError(`${a} needs a value.`)
      if (args.mode) throw new UsageError('Use exactly one of --url, --local or --version.')
      args.mode = a.slice(2)
      args.value = value
      i += 1
    } else if (a === '--help' || a === '-h') args.help = true
    else throw new UsageError(`Unknown option: ${a}`)
  }
  if (!args.help && !args.mode) throw new UsageError('Use one of --url, --local or --version.')
  return args
}

function describe(finding) {
  const lines = [`Target: ${finding.target}`]
  if (finding.headers && (finding.headers.poweredBy || finding.headers.server)) {
    if (finding.headers.poweredBy) lines.push(`X-Powered-By: ${finding.headers.poweredBy}`)
    if (finding.headers.server) lines.push(`Server: ${finding.headers.server}`)
  }
  if (finding.httpStatus) lines.push(`HTTP status: ${finding.httpStatus}`)
  lines.push(`Result: ${finding.status.toUpperCase()}. ${finding.reason}`)
  for (const tracker of finding.trackers ?? []) lines.push(`  ${tracker}`)
  return lines.join('\n')
}

export async function main(argv = process.argv.slice(2), { out = console.log, err = console.error } = {}) {
  let args
  try {
    args = parseArgs(argv)
  } catch (error) {
    if (error instanceof UsageError) { err(`${error.message}\n\n${USAGE}`); return 2 }
    throw error
  }
  if (args.help) { out(USAGE); return 0 }

  let findings
  try {
    if (args.mode === 'url') findings = [await checkUrl(args.value)]
    else if (args.mode === 'local') findings = checkLocal()
    else findings = [{ target: 'version given by hand', ...evaluate(args.value) }]
  } catch (error) {
    if (error instanceof UsageError) { err(`${error.message}\n\n${USAGE}`); return 2 }
    throw error
  }
  const foundBinaries = args.mode === 'local' && findings.length > 0
  if (args.mode === 'local' && findings.length === 0) {
    findings = [{ target: 'this machine', ...evaluate(null), reason: 'No PHP binary found on this machine (php, php-fpm, php-cgi). If your website runs PHP, check the server or the hosting panel. No result: this does not mean the site is safe.' }]
  }

  const status = worstStatus(findings)
  if (args.json) {
    out(JSON.stringify({ tool: 'php2shell-check', advisory: ADVISORY, mode: args.mode, status, findings }, null, 2))
  } else {
    out(`PHP2Shell check (${ADVISORY.cves.join(', ')}), PHP advisory of ${ADVISORY.published}`)
    for (const f of findings) out(`\n${describe(f)}`)
    if (foundBinaries) {
      out('\nNote: the PHP that serves your website (often php-fpm) can differ from the command-line php. Check every version above.')
    }
    out(`\nOverall: ${status.toUpperCase()}`)
    out(`Source: ${ADVISORY.url}`)
  }
  return EXIT_CODE[status]
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then((code) => { process.exitCode = code }, (error) => { console.error(error); process.exitCode = 2 })
}
