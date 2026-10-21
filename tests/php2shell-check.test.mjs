// Copyright 2026 toopster UG (haftungsbeschränkt). Licensed under the Apache License, Version 2.0 (see LICENSE).
// Independent tests for php2shell-check.mjs (node:test, no dependencies, Node.js 20 or newer).
//
// Run from the repository root:
//   node --test tests/*.test.mjs
//
// The tests follow the written specification (PHP advisory of 21 October 2026, first fixed releases
// 8.2.35, 8.3.36, 8.4.27, 8.5.12), not the implementation. The only network traffic is to HTTP servers this file starts
// on 127.0.0.1. No real PHP binary is ever started: checkLocal gets an injected fake, and the one CLI test that
// touches --local runs with PATH pointing at an empty directory.

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  ADVISORY,
  STATUS,
  UsageError,
  checkLocal,
  checkUrl,
  evaluate,
  main,
  parseArgs,
  versionFromCli,
  versionFromHeaders,
  worstStatus,
} from '../plugins/php2shell-check/skills/php2shell-check/scripts/php2shell-check.mjs'

const SCRIPT = fileURLToPath(new URL('../plugins/php2shell-check/skills/php2shell-check/scripts/php2shell-check.mjs', import.meta.url))

// ---------------------------------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------------------------------

/** Starts an HTTP server on 127.0.0.1 (port 0). `routes` maps a path to (req, res) => void. Every request is recorded. */
async function startServer(routes) {
  const hits = []
  const server = http.createServer((req, res) => {
    hits.push({ method: req.method, path: req.url })
    const route = routes[req.url.split('?')[0]]
    if (!route) {
      res.writeHead(404)
      res.end()
      return
    }
    route(req, res)
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const base = `http://127.0.0.1:${server.address().port}`
  return {
    server,
    base,
    hits,
    count: (method, path) => hits.filter((h) => h.method === method && h.path.split('?')[0] === path).length,
    total: (path) => hits.filter((h) => h.path.split('?')[0] === path).length,
    methods: (path) => hits.filter((h) => h.path.split('?')[0] === path).map((h) => h.method),
  }
}

/** Closes a server started by startServer, including hanging and keep-alive connections, so the process can exit. */
async function stopServer(s) {
  if (!s) return
  s.server.closeAllConnections?.()
  await new Promise((resolve) => s.server.close(resolve))
}

const reply = (status, headers = {}) => (req, res) => {
  res.writeHead(status, headers)
  res.end()
}

const byMethod = (handlers) => (req, res) => (handlers[req.method] ?? reply(500))(req, res)

async function waitFor(condition, ms = 3000) {
  const deadline = Date.now() + ms
  while (Date.now() < deadline) {
    if (condition()) return true
    await new Promise((r) => setTimeout(r, 20))
  }
  return condition()
}

/** A fetch stand-in that records its calls and answers from a list of [status, headers] pairs. */
function fakeFetch(...answers) {
  const calls = []
  const fetchImpl = async (url, init) => {
    calls.push({ url, init })
    const [status, headers] = answers[Math.min(calls.length - 1, answers.length - 1)]
    return new Response(null, { status, headers })
  }
  return { fetchImpl, calls }
}

const PHP_V_OUTPUT = (version, sapi = 'cli') =>
  `PHP ${version} (${sapi}) (built: Oct 21 2026 10:00:00) (NTS)\n` +
  'Copyright (c) The PHP Group\n' +
  'Zend Engine v4.4.26, Copyright (c) Zend Technologies\n'

const ENOENT = () => Object.assign(new Error('spawnSync ENOENT'), { code: 'ENOENT' })

/** Fake with the shape of child_process.spawnSync. `table` maps a binary name to a result or a function. */
function fakeRun(table) {
  const calls = []
  const run = (binary, args, options) => {
    calls.push({ binary, args, options })
    const entry = table[binary]
    if (typeof entry === 'function') return entry()
    return entry ?? { status: null, stdout: '', error: ENOENT() }
  }
  return { run, calls }
}

function runCli(args, env = process.env) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', env, timeout: 20_000 })
}

// ---------------------------------------------------------------------------------------------------------------------
// advisory data
// ---------------------------------------------------------------------------------------------------------------------

describe('advisory data', () => {
  it('names PHP2Shell and both CVEs', () => {
    assert.equal(ADVISORY.name, 'PHP2Shell')
    assert.deepEqual([...ADVISORY.cves], ['CVE-2026-109618', 'CVE-2026-109619'])
  })

  it('lists the first fixed release of each supported branch', () => {
    assert.deepEqual({ ...ADVISORY.fixed }, { '8.2': 35, '8.3': 36, '8.4': 27, '8.5': 12 })
  })

  it('exposes the four status strings', () => {
    assert.equal(STATUS.PATCHED, 'patched')
    assert.equal(STATUS.AFFECTED, 'affected')
    assert.equal(STATUS.UNSUPPORTED, 'unsupported')
    assert.equal(STATUS.UNKNOWN, 'unknown')
  })
})

// ---------------------------------------------------------------------------------------------------------------------
// evaluate
// ---------------------------------------------------------------------------------------------------------------------

describe('evaluate: boundaries of every supported branch', () => {
  const cases = [
    ['8.2.34', 'affected'], ['8.2.35', 'patched'],
    ['8.3.35', 'affected'], ['8.3.36', 'patched'],
    ['8.4.26', 'affected'], ['8.4.27', 'patched'],
    ['8.5.11', 'affected'], ['8.5.12', 'patched'],
  ]
  for (const [version, status] of cases) {
    it(`${version} is ${status}`, () => {
      assert.equal(evaluate(version).status, status)
    })
  }

  it('patch 0 of every supported branch is affected, far above the fix is patched', () => {
    for (const branch of ['8.2', '8.3', '8.4', '8.5']) {
      assert.equal(evaluate(`${branch}.0`).status, 'affected', `${branch}.0`)
      assert.equal(evaluate(`${branch}.99`).status, 'patched', `${branch}.99`)
      assert.equal(evaluate(branch).status, 'unknown', `${branch} alone has no patch number and is unparsable`)
    }
  })

  it('a branch is judged by its own fixed patch, not by the number of another branch', () => {
    // 8.2.36 is above 8.2.35 (patched) while 8.3.35 is below 8.3.36 (affected); 8.5.35 is above 8.5.12.
    assert.equal(evaluate('8.2.36').status, 'patched')
    assert.equal(evaluate('8.3.35').status, 'affected')
    assert.equal(evaluate('8.4.35').status, 'patched')
    assert.equal(evaluate('8.5.35').status, 'patched')
    assert.equal(evaluate('8.4.100').status, 'patched')
  })

  it('echoes the parsed version and always gives a reason', () => {
    for (const v of ['8.4.26', '8.4.27', '7.4.33', '8.6.0', '8.2.7-1~deb12u1']) {
      const r = evaluate(v)
      assert.equal(r.version, v)
      assert.equal(typeof r.reason, 'string')
      assert.ok(r.reason.length > 0)
    }
  })

  it('an affected result names the first fixed release of its branch', () => {
    assert.match(evaluate('8.2.34').reason, /8\.2\.35/)
    assert.match(evaluate('8.3.35').reason, /8\.3\.36/)
    assert.match(evaluate('8.4.26').reason, /8\.4\.27/)
    assert.match(evaluate('8.5.11').reason, /8\.5\.12/)
  })
})

describe('evaluate: unsupported branches', () => {
  for (const version of ['8.1.0', '8.1.27', '8.1.2', '8.0.30', '7.4.33', '7.0.0', '5.6.40', '5.2.17']) {
    it(`${version} is unsupported`, () => {
      assert.equal(evaluate(version).status, 'unsupported')
    })
  }
})

describe('evaluate: unknown', () => {
  for (const input of [null, undefined, '', '   ', 'garbage', '8', '8.4', 'abc.def.ghi']) {
    it(`${JSON.stringify(input)} is unknown`, () => {
      assert.equal(evaluate(input).status, 'unknown')
    })
  }

  it('no version at all: version is null and the reason does not call the system safe', () => {
    const r = evaluate(null)
    assert.equal(r.version, null)
    assert.match(r.reason, /does not mean .*safe/i)
  })

  for (const version of ['8.6.0', '8.6.3', '8.9.1', '8.10.0', '9.0.0', '10.1.2']) {
    it(`${version}, a branch newer than 8.5, is unknown`, () => {
      assert.equal(evaluate(version).status, 'unknown')
    })
  }

  for (const version of ['8.6.0RC4', '8.4.0beta1', '8.4.0alpha2', '8.4.0RC1', '8.4.0-dev', '8.5.0~rc1', '8.3.0.beta1']) {
    it(`pre-release ${version} is unknown`, () => {
      assert.equal(evaluate(version).status, 'unknown')
    })
  }

  it('a pre-release above the fixed patch is still unknown (not production)', () => {
    assert.equal(evaluate('8.4.30RC1').status, 'unknown')
  })
})

describe('evaluate: distribution package suffixes', () => {
  for (const version of ['8.2.7-1~deb12u1', '8.3.10.el9', '8.3.10-1.el9_4', '8.3.10-1.fc39', '8.2.7-0ubuntu0.22.04.1', '8.3.10-r0']) {
    it(`${version} (below the fix, distribution package) is unknown`, () => {
      const r = evaluate(version)
      assert.equal(r.status, 'unknown')
      assert.equal(r.version, version)
      assert.match(r.reason, /distribution/i)
    })
  }

  it('an unknown distribution result points to the security trackers', () => {
    const r = evaluate('8.2.7-1~deb12u1')
    assert.ok(Array.isArray(r.trackers) && r.trackers.length > 0)
    for (const t of r.trackers) assert.match(t, /https:\/\//)
  })

  it('a plain affected result carries no tracker list', () => {
    assert.equal(evaluate('8.4.26').trackers, undefined)
  })

  for (const version of ['8.2.35-1~deb12u1', '8.3.36.el9', '8.4.27.el9', '8.4.27-1ubuntu1', '8.5.12-1~deb13u1', '8.4.40-0ubuntu1']) {
    it(`${version} (at or above the fix, distribution package) is patched`, () => {
      assert.equal(evaluate(version).status, 'patched')
    })
  }

  it('a distribution package on a branch newer than 8.5 is unknown', () => {
    assert.equal(evaluate('8.6.1-1~deb13u1').status, 'unknown')
  })

  // 8.1 and older: a vendor build is "unknown" (vendors such as Ubuntu backport the fixes into 8.1), a plain upstream
  // number is "unsupported" (no official release with the fix).
  it('8.1.2-1ubuntu2.20 (Ubuntu 22.04 package of the old 8.1 branch) is unknown and points to the trackers', () => {
    const r = evaluate('8.1.2-1ubuntu2.20')
    assert.equal(r.status, 'unknown')
    assert.ok(Array.isArray(r.trackers) && r.trackers.length > 0)
  })

  it('7.4.33-1+deb11u5 (Debian 11 package of the old 7.4 branch) is unknown', () => {
    assert.equal(evaluate('7.4.33-1+deb11u5').status, 'unknown')
  })

  for (const version of ['8.3.10-1.amzn2023', '8.2.7-150500.1.1']) {
    it(`${version} (vendor build without a known distribution keyword, below the fix) is unknown`, () => {
      assert.equal(evaluate(version).status, 'unknown')
    })
  }

  it('the same version without a distribution suffix (8.1.2) is unsupported', () => {
    assert.equal(evaluate('8.1.2').status, 'unsupported')
  })
})

// ---------------------------------------------------------------------------------------------------------------------
// versionFromHeaders / versionFromCli / worstStatus
// ---------------------------------------------------------------------------------------------------------------------

describe('versionFromHeaders', () => {
  it('stops the version at a closing parenthesis, as in "(PHP/8.4.26)"', () => {
    assert.equal(versionFromHeaders({ poweredBy: null, server: 'Apache (PHP/8.4.26)' }), '8.4.26')
    assert.equal(evaluate(versionFromHeaders({ poweredBy: null, server: 'Apache (PHP/8.4.26)' })).status, 'affected')
  })

  it('reads PHP/x.y.z from X-Powered-By', () => {
    assert.equal(versionFromHeaders({ poweredBy: 'PHP/8.3.12', server: null }), '8.3.12')
  })

  it('reads PHP/x.y.z from a Server header with other software in front', () => {
    assert.equal(versionFromHeaders({ poweredBy: null, server: 'Apache/2.4.62 (Debian) PHP/8.2.7' }), '8.2.7')
  })

  it('falls through to Server when X-Powered-By does not name PHP', () => {
    assert.equal(versionFromHeaders({ poweredBy: 'Express', server: 'Apache/2.4.62 (Debian) PHP/8.2.7' }), '8.2.7')
  })

  it('keeps a distribution suffix', () => {
    assert.equal(versionFromHeaders({ poweredBy: 'PHP/8.2.7-1~deb12u1', server: null }), '8.2.7-1~deb12u1')
  })

  it('does not take the version of the web server for the PHP version', () => {
    assert.equal(versionFromHeaders({ poweredBy: null, server: 'nginx/1.25.3' }), null)
    assert.equal(versionFromHeaders({ poweredBy: null, server: 'Apache/2.4.62 (Debian)' }), null)
  })

  it('returns null without a PHP version', () => {
    assert.equal(versionFromHeaders({ poweredBy: null, server: 'nginx' }), null)
    assert.equal(versionFromHeaders({ poweredBy: null, server: 'Vercel' }), null)
    assert.equal(versionFromHeaders({ poweredBy: 'Next.js', server: 'Vercel' }), null)
    assert.equal(versionFromHeaders({ poweredBy: null, server: null }), null)
    assert.equal(versionFromHeaders({}), null)
  })

  it('returns null for PHP without a full x.y.z version', () => {
    assert.equal(versionFromHeaders({ poweredBy: 'PHP', server: null }), null)
    assert.equal(versionFromHeaders({ poweredBy: 'PHP/8.3', server: null }), null)
  })
})

describe('versionFromCli', () => {
  it('reads the first line of php -v', () => {
    assert.equal(versionFromCli('PHP 8.4.26 (cli) (built: Oct 21 2026 10:00:00) (NTS)'), '8.4.26')
  })

  it('reads the version from a full multi-line php -v output', () => {
    assert.equal(versionFromCli(PHP_V_OUTPUT('8.3.36')), '8.3.36')
    assert.equal(versionFromCli(PHP_V_OUTPUT('8.4.27', 'fpm-fcgi')), '8.4.27')
  })

  it('keeps a distribution suffix and pre-release markers', () => {
    assert.equal(versionFromCli(PHP_V_OUTPUT('8.2.7-1~deb12u1')), '8.2.7-1~deb12u1')
    assert.equal(versionFromCli('PHP 8.6.0RC4 (cli) (built: Oct 21 2026 10:00:00) (NTS)'), '8.6.0RC4')
  })

  it('returns null when there is no PHP line', () => {
    assert.equal(versionFromCli(''), null)
    assert.equal(versionFromCli(null), null)
    assert.equal(versionFromCli(undefined), null)
    assert.equal(versionFromCli('command not found: php'), null)
    assert.equal(versionFromCli('Python 3.12.1'), null)
  })
})

describe('worstStatus', () => {
  const f = (...statuses) => statuses.map((status) => ({ status }))

  it('an empty list is unknown', () => {
    assert.equal(worstStatus([]), 'unknown')
  })

  it('a single finding gives its own status', () => {
    for (const s of ['patched', 'affected', 'unsupported', 'unknown']) assert.equal(worstStatus(f(s)), s)
  })

  it('orders affected > unsupported > unknown > patched, in either position', () => {
    const order = ['affected', 'unsupported', 'unknown', 'patched']
    for (let i = 0; i < order.length; i += 1) {
      for (let j = i + 1; j < order.length; j += 1) {
        assert.equal(worstStatus(f(order[i], order[j])), order[i], `${order[i]} beats ${order[j]}`)
        assert.equal(worstStatus(f(order[j], order[i])), order[i], `${order[i]} beats ${order[j]} (reversed)`)
      }
    }
  })

  it('picks the worst of many', () => {
    assert.equal(worstStatus(f('patched', 'patched', 'patched')), 'patched')
    assert.equal(worstStatus(f('patched', 'unknown', 'patched')), 'unknown')
    assert.equal(worstStatus(f('patched', 'unsupported', 'unknown')), 'unsupported')
    assert.equal(worstStatus(f('unknown', 'patched', 'affected', 'unsupported')), 'affected')
  })
})

// ---------------------------------------------------------------------------------------------------------------------
// checkUrl against real local servers
// ---------------------------------------------------------------------------------------------------------------------

describe('checkUrl: one HEAD request, GET only on 405 or 501', () => {
  let s
  before(async () => {
    s = await startServer({
      '/affected': reply(200, { 'X-Powered-By': 'PHP/8.4.26' }),
      '/patched': reply(200, { 'X-Powered-By': 'PHP/8.4.27' }),
      '/apache': reply(200, { Server: 'Apache/2.4.62 (Debian) PHP/8.2.7' }),
      '/hidden': reply(200, { Server: 'nginx' }),
      '/unsupported': reply(200, { 'X-Powered-By': 'PHP/7.4.33' }),
      '/deb': reply(200, { 'X-Powered-By': 'PHP/8.2.7-1~deb12u1' }),
      '/head405': byMethod({ HEAD: reply(405), GET: reply(200, { 'X-Powered-By': 'PHP/8.5.12' }) }),
      '/head501': byMethod({ HEAD: reply(501), GET: reply(200, { 'X-Powered-By': 'PHP/8.5.11' }) }),
      '/both405': reply(405),
      '/head404': byMethod({ HEAD: reply(404), GET: reply(200, { 'X-Powered-By': 'PHP/8.4.26' }) }),
      '/head403': byMethod({ HEAD: reply(403), GET: reply(200, { 'X-Powered-By': 'PHP/8.4.26' }) }),
      '/head500': byMethod({ HEAD: reply(500), GET: reply(200, { 'X-Powered-By': 'PHP/8.4.26' }) }),
      '/head503': byMethod({ HEAD: reply(503), GET: reply(200, { 'X-Powered-By': 'PHP/8.4.26' }) }),
    })
  })
  after(() => stopServer(s))

  it('sends exactly one HEAD request and reports an affected version', async () => {
    const r = await checkUrl(`${s.base}/affected`)
    assert.equal(r.status, 'affected')
    assert.equal(r.version, '8.4.26')
    assert.equal(r.httpStatus, 200)
    assert.equal(r.headers.poweredBy, 'PHP/8.4.26')
    assert.deepEqual(s.methods('/affected'), ['HEAD'])
  })

  it('reports a patched version from X-Powered-By', async () => {
    const r = await checkUrl(`${s.base}/patched`)
    assert.equal(r.status, 'patched')
    assert.deepEqual(s.methods('/patched'), ['HEAD'])
  })

  it('reads the version from a Server header', async () => {
    const r = await checkUrl(`${s.base}/apache`)
    assert.equal(r.status, 'affected')
    assert.equal(r.version, '8.2.7')
    assert.match(r.headers.server, /Apache/)
  })

  it('reports unknown when the server hides PHP, never patched', async () => {
    const r = await checkUrl(`${s.base}/hidden`)
    assert.equal(r.status, 'unknown')
    assert.match(r.reason, /does not mean .*safe/i)
    assert.deepEqual(s.methods('/hidden'), ['HEAD'])
  })

  it('reports unsupported for PHP 7.4', async () => {
    assert.equal((await checkUrl(`${s.base}/unsupported`)).status, 'unsupported')
  })

  it('reports unknown for a distribution version below the fix', async () => {
    assert.equal((await checkUrl(`${s.base}/deb`)).status, 'unknown')
  })

  it('target is the absolute URL that was requested', async () => {
    const r = await checkUrl(`${s.base}/affected?x=1`)
    assert.equal(r.target, `${s.base}/affected?x=1`)
    assert.equal(r.status, 'affected')
  })

  it('falls back to exactly one GET when HEAD answers 405', async () => {
    const r = await checkUrl(`${s.base}/head405`)
    assert.deepEqual(s.methods('/head405'), ['HEAD', 'GET'])
    assert.equal(r.httpStatus, 200)
    assert.equal(r.status, 'patched')
    assert.equal(r.version, '8.5.12')
  })

  it('falls back to exactly one GET when HEAD answers 501', async () => {
    const r = await checkUrl(`${s.base}/head501`)
    assert.deepEqual(s.methods('/head501'), ['HEAD', 'GET'])
    assert.equal(r.status, 'affected')
    assert.equal(r.version, '8.5.11')
  })

  it('does not try a third request when GET is refused as well', async () => {
    const r = await checkUrl(`${s.base}/both405`)
    assert.deepEqual(s.methods('/both405'), ['HEAD', 'GET'])
    assert.equal(r.httpStatus, 405)
    assert.equal(r.status, 'unknown')
  })

  for (const code of [403, 404, 500, 503]) {
    it(`does NOT fall back to GET when HEAD answers ${code}`, async () => {
      const path = `/head${code}`
      const r = await checkUrl(`${s.base}${path}`)
      assert.deepEqual(s.methods(path), ['HEAD'])
      assert.equal(r.httpStatus, code)
      assert.equal(r.status, 'unknown')
    })
  }
})

describe('checkUrl: redirects are reported, never followed', () => {
  let origin
  let landing
  before(async () => {
    landing = await startServer({
      '/landing': reply(200, { 'X-Powered-By': 'PHP/8.4.26' }),
      '/other': reply(200, { 'X-Powered-By': 'PHP/8.4.26' }),
    })
    const routes = {
      '/rel': reply(301, { Location: '/x/y?z=1' }),
      '/x/y': reply(200, { 'X-Powered-By': 'PHP/8.4.26' }),
      '/noloc': reply(302),
      '/hidden302': reply(302, { Location: `${landing.base}/other`, Server: 'nginx' }),
      '/patched301': reply(301, { Location: `${landing.base}/other`, 'X-Powered-By': 'PHP/8.4.27' }),
    }
    for (const code of [301, 302, 307, 308]) routes[`/r${code}`] = reply(code, { Location: `${landing.base}/landing` })
    origin = await startServer(routes)
  })
  after(async () => {
    await stopServer(origin)
    await stopServer(landing)
  })

  for (const code of [301, 302, 307, 308]) {
    it(`${code}: reports the absolute Location as redirect and does not request it`, async () => {
      const r = await checkUrl(`${origin.base}/r${code}`)
      assert.equal(r.httpStatus, code)
      assert.equal(r.redirect, `${landing.base}/landing`)
      assert.deepEqual(origin.methods(`/r${code}`), ['HEAD'], 'only one request to the redirecting URL')
      assert.equal(landing.total('/landing'), 0, 'the redirect target was never requested')
    })
  }

  it('a redirect without version information is unknown and the reason names the new address', async () => {
    const r = await checkUrl(`${origin.base}/hidden302`)
    assert.equal(r.status, 'unknown')
    assert.equal(r.redirect, `${landing.base}/other`)
    assert.ok(r.reason.includes(r.redirect))
    assert.equal(landing.total('/other'), 0)
  })

  it('a relative Location is resolved to an absolute URL and is not requested', async () => {
    const r = await checkUrl(`${origin.base}/rel`)
    assert.equal(r.redirect, `${origin.base}/x/y?z=1`)
    assert.equal(origin.total('/x/y'), 0)
    assert.deepEqual(origin.methods('/rel'), ['HEAD'])
  })

  it('a redirect response that itself names PHP is evaluated from its own headers', async () => {
    const r = await checkUrl(`${origin.base}/patched301`)
    assert.equal(r.status, 'patched')
    assert.equal(r.redirect, `${landing.base}/other`)
    assert.equal(landing.total('/other'), 0)
  })

  it('a 3xx without Location has no redirect field', async () => {
    const r = await checkUrl(`${origin.base}/noloc`)
    assert.equal(r.httpStatus, 302)
    assert.equal(r.redirect, undefined)
  })
})

describe('checkUrl: the response body is never read', () => {
  let s
  const state = { closed: false, started: false }
  before(async () => {
    s = await startServer({
      // HEAD is refused, so checkUrl does the GET fallback; the GET answers with headers and an endless body.
      '/endless': (req, res) => {
        if (req.method !== 'GET') {
          res.writeHead(405)
          res.end()
          return
        }
        state.started = true
        res.writeHead(200, { 'X-Powered-By': 'PHP/8.5.12', 'Content-Type': 'text/plain' })
        res.flushHeaders()
        const timer = setInterval(() => res.write('x'.repeat(1024)), 10)
        res.on('close', () => {
          clearInterval(timer)
          state.closed = true
        })
      },
    })
  })
  after(() => stopServer(s))

  it('returns from the headers while the server is still streaming, then releases the connection', async () => {
    const started = Date.now()
    const r = await checkUrl(`${s.base}/endless`, { timeoutMs: 8000 })
    const elapsed = Date.now() - started
    assert.equal(r.status, 'patched', 'derived from the headers')
    assert.equal(r.httpStatus, 200)
    assert.ok(elapsed < 4000, `took ${elapsed} ms: the body must not be consumed to its end`)
    assert.deepEqual(s.methods('/endless'), ['HEAD', 'GET'])
    assert.ok(state.started)
    assert.ok(await waitFor(() => state.closed, 3000), 'the connection to the streaming server was closed')
  })

  it('does not touch the body of a response (no pull, no text/json/arrayBuffer/blob/formData/clone)', async () => {
    let pulls = 0
    const body = new ReadableStream(
      {
        pull(controller) {
          pulls += 1
          controller.enqueue(new TextEncoder().encode('secret body'))
        },
      },
      { highWaterMark: 0 },
    )
    const response = new Response(body, { status: 200, headers: { 'x-powered-by': 'PHP/8.4.27' } })
    const used = []
    for (const name of ['text', 'json', 'arrayBuffer', 'blob', 'formData', 'bytes', 'clone']) {
      response[name] = () => {
        used.push(name)
        return Promise.resolve(null)
      }
    }
    const r = await checkUrl('http://example.invalid/', { fetchImpl: async () => response })
    assert.equal(r.status, 'patched')
    assert.equal(pulls, 0, 'nothing was read from the body stream')
    assert.deepEqual(used, [])
  })
})

describe('checkUrl: failures are never reported as safe', () => {
  let s
  before(async () => {
    s = await startServer({
      '/hang': () => {}, // never answers
      '/head405-get-hangs': (req, res) => {
        if (req.method === 'HEAD') {
          res.writeHead(405)
          res.end()
        }
        // GET never answers
      },
    })
  })
  after(() => stopServer(s))

  it('a server that never answers gives unknown with a timeout reason, after about timeoutMs', async () => {
    const started = Date.now()
    const r = await checkUrl(`${s.base}/hang`, { timeoutMs: 300 })
    const elapsed = Date.now() - started
    assert.equal(r.status, 'unknown')
    assert.equal(r.httpStatus, null)
    assert.match(r.reason, /timeout/i)
    assert.match(r.reason, /does not mean .*safe/i)
    assert.ok(elapsed >= 250 && elapsed < 3000, `answered after ${elapsed} ms`)
    assert.deepEqual(s.methods('/hang'), ['HEAD'], 'a timed-out HEAD is not retried as GET')
  })

  it('a timeout on the GET fallback gives unknown as well', async () => {
    const r = await checkUrl(`${s.base}/head405-get-hangs`, { timeoutMs: 300 })
    assert.equal(r.status, 'unknown')
    assert.match(r.reason, /timeout/i)
    assert.deepEqual(s.methods('/head405-get-hangs'), ['HEAD', 'GET'])
  })

  it('a refused connection gives unknown with a network error reason', async () => {
    const gone = await startServer({})
    const url = `${gone.base}/`
    await stopServer(gone)
    const r = await checkUrl(url, { timeoutMs: 2000 })
    assert.equal(r.status, 'unknown')
    assert.equal(r.httpStatus, null)
    assert.match(r.reason, /network error/i)
    assert.match(r.reason, /does not mean .*safe/i)
  })

  it('a failing fetch implementation gives unknown, and a TimeoutError is named as timeout', async () => {
    const boom = await checkUrl('http://example.invalid/', {
      fetchImpl: async () => {
        throw new TypeError('fetch failed')
      },
    })
    assert.equal(boom.status, 'unknown')
    assert.match(boom.reason, /network error/i)

    const slow = await checkUrl('http://example.invalid/', {
      fetchImpl: async () => {
        throw new DOMException('timed out', 'TimeoutError')
      },
    })
    assert.equal(slow.status, 'unknown')
    assert.match(slow.reason, /timeout/i)
  })
})

describe('checkUrl: invalid input', () => {
  for (const input of ['ftp://example.com/', 'file:///etc/passwd', 'javascript:alert(1)', 'ws://example.com/', 'data:text/plain,hi']) {
    it(`${input} throws UsageError and sends nothing`, async () => {
      const { fetchImpl, calls } = fakeFetch([200, {}])
      await assert.rejects(checkUrl(input, { fetchImpl }), UsageError)
      assert.equal(calls.length, 0)
    })
  }

  for (const input of ['not a url', '', 'example.com', '//example.com', '/relative/path']) {
    it(`${JSON.stringify(input)} throws UsageError and sends nothing`, async () => {
      const { fetchImpl, calls } = fakeFetch([200, {}])
      await assert.rejects(checkUrl(input, { fetchImpl }), UsageError)
      assert.equal(calls.length, 0)
    })
  }

  it('UsageError is an Error', () => {
    assert.ok(new UsageError('x') instanceof Error)
  })
})

describe('checkUrl: request shape (fake fetch)', () => {
  it('sends a single HEAD with redirect handling set to manual and an abort signal', async () => {
    const { fetchImpl, calls } = fakeFetch([200, { 'x-powered-by': 'PHP/8.4.27' }])
    await checkUrl('http://example.invalid/page', { fetchImpl })
    assert.equal(calls.length, 1)
    assert.equal(calls[0].url, 'http://example.invalid/page')
    assert.equal(calls[0].init.method, 'HEAD')
    assert.equal(calls[0].init.redirect, 'manual')
    assert.ok(calls[0].init.signal instanceof AbortSignal)
  })

  it('the GET fallback keeps redirect handling manual', async () => {
    const { fetchImpl, calls } = fakeFetch([405, {}], [200, { 'x-powered-by': 'PHP/8.4.27' }])
    await checkUrl('http://example.invalid/', { fetchImpl })
    assert.deepEqual(calls.map((c) => c.init.method), ['HEAD', 'GET'])
    assert.equal(calls[1].init.redirect, 'manual')
  })

  const matrix = [
    [405, ['HEAD', 'GET']], [501, ['HEAD', 'GET']],
    [200, ['HEAD']], [204, ['HEAD']], [301, ['HEAD']], [302, ['HEAD']], [400, ['HEAD']], [401, ['HEAD']],
    [403, ['HEAD']], [404, ['HEAD']], [429, ['HEAD']], [500, ['HEAD']], [502, ['HEAD']], [503, ['HEAD']],
  ]
  for (const [code, methods] of matrix) {
    it(`HEAD ${code} leads to ${methods.join(' then ')}`, async () => {
      const { fetchImpl, calls } = fakeFetch([code, code >= 300 && code < 400 ? { location: '/next' } : {}], [200, {}])
      await checkUrl('http://example.invalid/', { fetchImpl })
      assert.deepEqual(calls.map((c) => c.init.method), methods)
    })
  }
})

// ---------------------------------------------------------------------------------------------------------------------
// checkLocal with injected run function
// ---------------------------------------------------------------------------------------------------------------------

describe('checkLocal', () => {
  it('returns one finding per binary that reports a version', () => {
    const { run } = fakeRun({
      php: { status: 0, stdout: PHP_V_OUTPUT('8.4.26') },
      'php-fpm': { status: 0, stdout: PHP_V_OUTPUT('8.4.27', 'fpm-fcgi') },
    })
    const findings = checkLocal({ run, binaries: ['php', 'php-fpm', 'php-cgi'] })
    assert.equal(findings.length, 2)
    assert.equal(findings[0].target, 'php')
    assert.equal(findings[0].status, 'affected')
    assert.equal(findings[0].version, '8.4.26')
    assert.equal(findings[1].target, 'php-fpm')
    assert.equal(findings[1].status, 'patched')
    assert.equal(worstStatus(findings), 'affected')
  })

  it('calls every binary with -v only', () => {
    const { run, calls } = fakeRun({ php: { status: 0, stdout: PHP_V_OUTPUT('8.4.27') } })
    checkLocal({ run, binaries: ['php', 'php8.3'] })
    assert.deepEqual(calls.map((c) => c.binary), ['php', 'php8.3'])
    for (const c of calls) assert.deepEqual(c.args, ['-v'])
  })

  it('skips a binary that is missing (error set)', () => {
    const { run } = fakeRun({})
    assert.deepEqual(checkLocal({ run, binaries: ['php', 'php-fpm'] }), [])
  })

  it('skips a binary whose result has an error, even with valid output and status 0', () => {
    const { run } = fakeRun({ php: { status: 0, stdout: PHP_V_OUTPUT('8.4.27'), error: new Error('ETIMEDOUT') } })
    assert.deepEqual(checkLocal({ run, binaries: ['php'] }), [])
  })

  it('skips a binary that exits with a non-zero status, even when stdout looks like a version', () => {
    const { run } = fakeRun({
      php: { status: 1, stdout: PHP_V_OUTPUT('8.4.26') },
      'php-fpm': { status: 127, stdout: '' },
      'php-cgi': { status: null, stdout: PHP_V_OUTPUT('8.4.26') },
    })
    assert.deepEqual(checkLocal({ run, binaries: ['php', 'php-fpm', 'php-cgi'] }), [])
  })

  it('skips a binary when run throws and carries on with the next one', () => {
    const { run } = fakeRun({
      php: () => {
        throw new Error('spawn exploded')
      },
      'php-fpm': { status: 0, stdout: PHP_V_OUTPUT('8.3.36', 'fpm-fcgi') },
    })
    const findings = checkLocal({ run, binaries: ['php', 'php-fpm'] })
    assert.equal(findings.length, 1)
    assert.equal(findings[0].target, 'php-fpm')
    assert.equal(findings[0].status, 'patched')
  })

  it('gives no finding for a binary that runs but prints no PHP version', () => {
    const { run } = fakeRun({ php: { status: 0, stdout: 'something else entirely\n' } })
    assert.deepEqual(checkLocal({ run, binaries: ['php'] }), [])
  })

  it('evaluates distribution and pre-release versions like evaluate does', () => {
    const { run } = fakeRun({
      php: { status: 0, stdout: PHP_V_OUTPUT('8.2.7-1~deb12u1') },
      'php-fpm': { status: 0, stdout: PHP_V_OUTPUT('8.6.0RC4', 'fpm-fcgi') },
      'php-cgi': { status: 0, stdout: PHP_V_OUTPUT('7.4.33', 'cgi-fcgi') },
    })
    const findings = checkLocal({ run, binaries: ['php', 'php-fpm', 'php-cgi'] })
    assert.deepEqual(findings.map((f) => f.status), ['unknown', 'unknown', 'unsupported'])
  })

  it('with no binaries there are no findings', () => {
    const { run, calls } = fakeRun({})
    assert.deepEqual(checkLocal({ run, binaries: [] }), [])
    assert.equal(calls.length, 0)
  })

  it('by default looks for php, php-fpm and php-cgi (injected run, nothing is spawned)', () => {
    const { run, calls } = fakeRun({})
    assert.deepEqual(checkLocal({ run }), [])
    const names = calls.map((c) => c.binary)
    for (const expected of ['php', 'php-fpm', 'php-cgi']) assert.ok(names.includes(expected), `${expected} is tried`)
    for (const c of calls) assert.deepEqual(c.args, ['-v'])
  })
})

// ---------------------------------------------------------------------------------------------------------------------
// parseArgs
// ---------------------------------------------------------------------------------------------------------------------

describe('parseArgs', () => {
  it('parses each mode with its value and the json flag', () => {
    assert.deepEqual(parseArgs(['--version', '8.4.26']), { json: false, mode: 'version', value: '8.4.26' })
    assert.deepEqual(parseArgs(['--url', 'https://example.com', '--json']), { json: true, mode: 'url', value: 'https://example.com' })
    assert.deepEqual(parseArgs(['--json', '--local']), { json: true, mode: 'local' })
  })

  it('--help and -h are accepted without a mode', () => {
    assert.equal(parseArgs(['--help']).help, true)
    assert.equal(parseArgs(['-h']).help, true)
  })

  const rejected = [
    ['no arguments', []],
    ['only --json (no mode)', ['--json']],
    ['unknown option', ['--bogus']],
    ['unknown option after a valid mode', ['--version', '8.4.26', '--bogus']],
    ['stray positional argument', ['--version', '8.4.26', 'extra']],
    ['--url without a value', ['--url']],
    ['--version without a value', ['--version']],
    ['--url followed by another option', ['--url', '--json']],
    ['--version followed by another option', ['--version', '--json']],
    ['--url followed by --version (value missing)', ['--url', '--version', '8.4.26']],
    ['--url and --version', ['--url', 'https://example.com', '--version', '8.4.26']],
    ['--version and --url', ['--version', '8.4.26', '--url', 'https://example.com']],
    ['--url twice with different values', ['--url', 'https://a.example', '--url', 'https://b.example']],
    ['--local then --version', ['--local', '--version', '8.4.26']],
    ['--local then --url', ['--local', '--url', 'https://example.com']],
    ['--version then --local', ['--version', '8.4.26', '--local']],
    ['--url then --local', ['--url', 'https://example.com', '--local']],
  ]
  for (const [name, argv] of rejected) {
    it(`rejects ${name}`, () => {
      assert.throws(() => parseArgs(argv), UsageError)
    })
  }
})

// ---------------------------------------------------------------------------------------------------------------------
// main (in-process, with captured out/err)
// ---------------------------------------------------------------------------------------------------------------------

function capture() {
  const out = []
  const err = []
  return { out, err, io: { out: (s) => out.push(String(s)), err: (s) => err.push(String(s)) } }
}

describe('main: --version', () => {
  const cases = [
    ['8.4.26', 1, 'AFFECTED'],
    ['8.4.27', 0, 'PATCHED'],
    ['8.2.34', 1, 'AFFECTED'],
    ['8.5.12', 0, 'PATCHED'],
    ['8.1.9', 1, 'UNSUPPORTED'],
    ['7.4.33', 1, 'UNSUPPORTED'],
    ['8.6.0', 3, 'UNKNOWN'],
    ['8.4.0beta1', 3, 'UNKNOWN'],
    ['garbage', 3, 'UNKNOWN'],
    ['8.2.7-1~deb12u1', 3, 'UNKNOWN'],
    ['8.2.35-1~deb12u1', 0, 'PATCHED'],
  ]
  for (const [version, code, word] of cases) {
    it(`${version} exits ${code} and prints ${word}`, async () => {
      const { out, err, io } = capture()
      assert.equal(await main(['--version', version], io), code)
      assert.match(out.join('\n'), new RegExp(`Overall: ${word}`))
      assert.deepEqual(err, [])
    })
  }

  it('--json prints one JSON document with tool, advisory, mode, status and findings', async () => {
    const { out, err, io } = capture()
    const code = await main(['--json', '--version', '8.4.26'], io)
    assert.equal(code, 1)
    assert.deepEqual(err, [])
    assert.equal(out.length, 1)
    const doc = JSON.parse(out[0])
    assert.equal(doc.tool, 'php2shell-check')
    assert.equal(doc.mode, 'version')
    assert.equal(doc.status, 'affected')
    assert.equal(doc.advisory.name, 'PHP2Shell')
    assert.deepEqual(doc.advisory.cves, ['CVE-2026-109618', 'CVE-2026-109619'])
    assert.deepEqual(doc.advisory.fixed, { '8.2': 35, '8.3': 36, '8.4': 27, '8.5': 12 })
    assert.ok(Array.isArray(doc.findings))
    assert.equal(doc.findings.length, 1)
    assert.equal(doc.findings[0].status, 'affected')
    assert.equal(doc.findings[0].version, '8.4.26')
  })

  it('--json status mirrors the exit code for patched and unknown', async () => {
    for (const [version, code, status] of [['8.4.27', 0, 'patched'], ['8.6.0', 3, 'unknown'], ['8.0.30', 1, 'unsupported']]) {
      const { out, io } = capture()
      assert.equal(await main(['--version', version, '--json'], io), code)
      assert.equal(JSON.parse(out[0]).status, status)
    }
  })
})

describe('main: help and usage errors', () => {
  it('--help returns 0 and prints the usage on out', async () => {
    const { out, err, io } = capture()
    assert.equal(await main(['--help'], io), 0)
    assert.match(out.join('\n'), /Usage:/)
    assert.match(out.join('\n'), /--url/)
    assert.match(out.join('\n'), /--local/)
    assert.match(out.join('\n'), /--version/)
    assert.deepEqual(err, [])
  })

  it('-h returns 0', async () => {
    const { io } = capture()
    assert.equal(await main(['-h'], io), 0)
  })

  // Only argument lists that fail before anything runs belong here: main never reaches checkLocal for them.
  const usageErrors = [
    ['no mode', []],
    ['only --json', ['--json']],
    ['unknown option', ['--bogus']],
    ['--url without a value', ['--url']],
    ['--version without a value', ['--version']],
    ['--version followed by an option', ['--version', '--json']],
    ['--local then --version (two modes)', ['--local', '--version', '8.4.26']],
    ['--version then --url (two modes)', ['--version', '8.4.26', '--url', 'http://127.0.0.1:9/']],
    ['--url with a non-http scheme', ['--url', 'ftp://127.0.0.1/']],
    ['--url with garbage', ['--url', 'not a url']],
  ]
  for (const [name, argv] of usageErrors) {
    it(`${name} returns 2, writes the usage to err and prints no result`, async () => {
      const { out, err, io } = capture()
      assert.equal(await main(argv, io), 2)
      assert.deepEqual(out, [])
      assert.equal(err.length, 1)
      assert.match(err[0], /Usage:/)
    })
  }
})

describe('main: --url against a local server', () => {
  let s
  before(async () => {
    s = await startServer({
      '/affected': reply(200, { 'X-Powered-By': 'PHP/8.4.26' }),
      '/patched': reply(200, { Server: 'Apache/2.4.62 (Debian) PHP/8.5.12' }),
      '/hidden': reply(200, { Server: 'nginx' }),
      '/old': reply(200, { 'X-Powered-By': 'PHP/7.4.33' }),
      '/moved': (req, res) => {
        res.writeHead(301, { Location: '/landing' })
        res.end()
      },
      '/landing': reply(200, { 'X-Powered-By': 'PHP/8.4.27' }),
    })
  })
  after(() => stopServer(s))

  it('affected version: exit 1', async () => {
    const { out, err, io } = capture()
    assert.equal(await main(['--url', `${s.base}/affected`], io), 1)
    assert.match(out.join('\n'), /Overall: AFFECTED/)
    assert.match(out.join('\n'), /X-Powered-By: PHP\/8\.4\.26/)
    assert.deepEqual(err, [])
    assert.deepEqual(s.methods('/affected'), ['HEAD'])
  })

  it('patched version in a Server header: exit 0', async () => {
    const { out, io } = capture()
    assert.equal(await main(['--url', `${s.base}/patched`], io), 0)
    assert.match(out.join('\n'), /Overall: PATCHED/)
  })

  it('hidden version: exit 3', async () => {
    const { out, io } = capture()
    assert.equal(await main(['--url', `${s.base}/hidden`], io), 3)
    assert.match(out.join('\n'), /Overall: UNKNOWN/)
  })

  it('unsupported version: exit 1', async () => {
    const { io } = capture()
    assert.equal(await main(['--url', `${s.base}/old`], io), 1)
  })

  it('--json carries mode url, the finding, and the redirect without following it', async () => {
    const { out, err, io } = capture()
    assert.equal(await main(['--url', `${s.base}/moved`, '--json'], io), 3)
    assert.deepEqual(err, [])
    const doc = JSON.parse(out[0])
    assert.equal(doc.tool, 'php2shell-check')
    assert.equal(doc.mode, 'url')
    assert.equal(doc.status, 'unknown')
    assert.equal(doc.findings.length, 1)
    assert.equal(doc.findings[0].target, `${s.base}/moved`)
    assert.equal(doc.findings[0].httpStatus, 301)
    assert.equal(doc.findings[0].redirect, `${s.base}/landing`)
    assert.equal(s.total('/landing'), 0, 'the redirect target was not requested')
  })

  it('--json for an affected site', async () => {
    const { out, io } = capture()
    assert.equal(await main(['--json', '--url', `${s.base}/affected`], io), 1)
    const doc = JSON.parse(out[0])
    assert.equal(doc.mode, 'url')
    assert.equal(doc.status, 'affected')
    assert.equal(doc.findings[0].version, '8.4.26')
  })
})

// ---------------------------------------------------------------------------------------------------------------------
// the script as a real command line program
// ---------------------------------------------------------------------------------------------------------------------

describe('CLI (real child process)', () => {
  let emptyPathDir
  before(() => {
    emptyPathDir = mkdtempSync(join(tmpdir(), 'php2shell-emptypath-'))
  })
  after(() => {
    if (emptyPathDir) rmSync(emptyPathDir, { recursive: true, force: true })
  })

  it('--version 8.4.26 exits 1', () => {
    const r = runCli(['--version', '8.4.26'])
    assert.equal(r.status, 1, r.stderr)
    assert.match(r.stdout, /Overall: AFFECTED/)
  })

  it('--version 8.4.27 exits 0', () => {
    const r = runCli(['--version', '8.4.27'])
    assert.equal(r.status, 0, r.stderr)
    assert.match(r.stdout, /Overall: PATCHED/)
  })

  it('--version 8.6.0 exits 3', () => {
    assert.equal(runCli(['--version', '8.6.0']).status, 3)
  })

  it('no arguments exits 2 and shows the usage on stderr', () => {
    const r = runCli([])
    assert.equal(r.status, 2)
    assert.match(r.stderr, /Usage:/)
    assert.equal(r.stdout, '')
  })

  it('--help exits 0', () => {
    const r = runCli(['--help'])
    assert.equal(r.status, 0)
    assert.match(r.stdout, /Usage:/)
  })

  it('--json prints parseable JSON on stdout', () => {
    const r = runCli(['--version', '8.4.26', '--json'])
    assert.equal(r.status, 1)
    assert.equal(JSON.parse(r.stdout).status, 'affected')
  })

  it('importing the module does not run the CLI (no output, no exit code side effect)', () => {
    const r = spawnSync(
      process.execPath,
      ['--input-type=module', '-e', `await import(${JSON.stringify(new URL('../plugins/php2shell-check/skills/php2shell-check/scripts/php2shell-check.mjs', import.meta.url).href)})`],
      { encoding: 'utf8', timeout: 20_000 },
    )
    assert.equal(r.status, 0, r.stderr)
    assert.equal(r.stdout, '')
    assert.equal(r.stderr, '')
  })

  // PATH points at an empty directory, so no PHP binary can be found or started.
  it('--local with no PHP binary on the machine exits 3 and says nothing was found', () => {
    const r = runCli(['--local'], { ...process.env, PATH: emptyPathDir })
    assert.equal(r.status, 3, r.stderr)
    assert.match(r.stdout, /No PHP binary found/)
    assert.match(r.stdout, /Overall: UNKNOWN/)
  })

  it('--local --json with no PHP binary reports mode local and status unknown', () => {
    const r = runCli(['--local', '--json'], { ...process.env, PATH: emptyPathDir })
    assert.equal(r.status, 3, r.stderr)
    const doc = JSON.parse(r.stdout)
    assert.equal(doc.mode, 'local')
    assert.equal(doc.status, 'unknown')
    assert.equal(doc.findings.length, 1)
  })

  // Two modes must be a usage error in either order. Run with an empty PATH so that, if the checker wrongly accepts
  // the combination, it still cannot start any PHP binary.
  it('--local then --version is a usage error (exit 2)', () => {
    const r = runCli(['--local', '--version', '8.4.26'], { ...process.env, PATH: emptyPathDir })
    assert.equal(r.status, 2, r.stdout)
  })

  it('--version then --local is a usage error (exit 2)', () => {
    const r = runCli(['--version', '8.4.26', '--local'], { ...process.env, PATH: emptyPathDir })
    assert.equal(r.status, 2, `exit ${r.status}, stdout: ${r.stdout}`)
  })
})
