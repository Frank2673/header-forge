# header-forge

English | [简体中文](README.md)

[![CI](https://github.com/Frank2673/header-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/Frank2673/header-forge/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![zero dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)
![tests](https://img.shields.io/badge/tests-204%20passed-brightgreen)

**Security response headers as code** — declare once, generate for multiple platforms, verify the live response, prove it locally.
It can also **reverse-import** an existing configuration (so you can take over someone else's project), and a round-trip consistency guard keeps generation and parsing strictly symmetric.

> Companion project: [surface-watch](https://github.com/Frank2673/surface-watch) (finds the problems) → **header-forge** (fixes them and prevents regressions)

---

## TL;DR (30 seconds)

| | |
|---|---|
| **What** | A zero-dependency CLI that turns one security-header policy into native config for 6 platforms, then verifies the live response against that policy. |
| **Who it is for** | Developers and platform teams who host on Cloudflare Pages / Netlify / Vercel / nginx / Caddy / Apache and want their security headers to be code — declared, generated, and CI-gated. |
| **Problem it solves** | "The config is written but not in effect." A built-in simulator parses the **generated artifact** and applies it to a real HTTP response, so you can prove it works without buying a domain or deploying. |
| **Requires** | Node ≥ 20. No `npm install`, no third-party packages. |
| **Does not do** | It does not deploy for you. GitHub Pages is not supported, because GitHub Pages does not support custom response headers at all. |

Declare, generate, prove — all offline:

```bash
git clone https://github.com/Frank2673/header-forge.git && cd header-forge
node src/index.mjs generate --policy headers.policy.json --out dist
node src/index.mjs simulate --config dist/_headers --policy headers.policy.json
```

Real output of that command pair (captured from this repository, verbatim):

```
🧪 用 _headers 启动本地模拟服务…
   从配置中解析出 7 个响应头

✅ 完全符合策略 | 符合 7 | 缺失 0 | 值不符 0

✅ 生成的配置经本地实测可完全满足策略（配置语法与取值均正确）
```

> **Translator's note (factual, not part of the Chinese README):** the lines above read
> `starting a local simulator with _headers…` / `parsed 7 response headers from the config` /
> `✓ fully conforms to the policy | match 7 | missing 0 | value mismatch 0` /
> `✓ the generated config was measured locally to fully satisfy the policy (both config syntax and values are correct)`.
> **The CLI's console output is currently Chinese-only** — a real limitation of the tool, not a documentation choice.

---

## The real problem it solves

Scanning your own site with surface-watch produced 6 missing response headers:

```
❌ 缺少 Content-Security-Policy        ❌ 缺少 X-Frame-Options
❌ 缺少 X-Content-Type-Options         ❌ 缺少 Referrer-Policy
❌ 缺少 Permissions-Policy             ⚠️ HSTS 缺 includeSubDomains
```

(That is: missing Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and Permissions-Policy, plus HSTS missing `includeSubDomains`.)

But **there is a chasm between finding a problem and fixing it**: the site is hosted on GitHub Pages, and **GitHub Pages does not support custom response headers**.

Hence this project. It does not pretend the problem does not exist; it splits "fixing" into three verifiable steps:

| Step | Approach | Artifact |
|---|---|---|
| **Declare** | The policy is code, carrying severity and rationale | `headers.policy.json` |
| **Land it** | Generate native config for 6 platforms | `_headers` / `vercel.json` / nginx / caddy / `.htaccess` |
| **Verify** | Live consistency check + local self-proof | conformance report / CI gate |

## The point most worth making: provable locally

"Config written but not in effect" is the most common way this kind of work fails. So the project ships a **simulator**:

```
policy → generator → config file (the real artifact) → parse & apply to an HTTP response → verifier → ✅ 100% conformance
```

```bash
$ node src/index.mjs generate --policy headers.policy.json --out dist
$ node src/index.mjs simulate --config dist/_headers --policy headers.policy.json

🧪 用 _headers 启动本地模拟服务…
   从配置中解析出 7 个响应头
✅ 完全符合策略 | 符合 7 | 缺失 0 | 值不符 0
```

The crucial detail is that the simulator **parses the generated config file itself** rather than reusing the policy object — any mis-write, omission or escaping error in a generator is exposed right here. **No domain purchase, no deployment, and you have proven the configuration works.**

## Quick start

Zero dependencies, no `npm install` needed (Node ≥ 20):

```bash
# 1. Generate the per-platform configs
node src/index.mjs generate --policy headers.policy.json --out dist

# 2. Prove locally that the generated config really satisfies the policy
node src/index.mjs simulate --config dist/_headers --policy headers.policy.json

# 3. Verify the live response headers (CI gate: exit code 1 on mismatch)
node src/index.mjs verify --policy headers.policy.json

# 4. Generate a CSP for a page that will not break the site (with inline-script hashes)
node src/index.mjs advise --html path/to/index.html
```

## Generator matrix

| Platform | Artifact | Notes |
|---|---|---|
| **Cloudflare Pages** | `_headers` | Supported on the free plan, **no domain of your own required** (`*.pages.dev` works) |
| **Netlify** | `_headers` | Supported on the free plan; path matching is stricter than Cloudflare's |
| **Vercel** | `vercel.json` | Also emits a mergeable fragment, so an existing config is not overwritten |
| **Nginx** | `add_header` directives | Warns about the `add_header` inheritance trap; values are escaped to prevent config injection |
| **Caddy** | `Caddyfile` fragment | Supports `-HeaderName` to remove a response header outright |
| **Apache** | `.htaccess` | `mod_headers` + `<IfModule>` guard; the prerequisite (`AllowOverride FileInfo`) is written into the artifact's comments and into the limitations below |

> GitHub Pages is not on this list — because it **does not support** custom response headers. The migration path is in [MIGRATION.md](MIGRATION.md).

### Apache `.htaccess`: two default trade-offs

It is the only **file-level** artifact, so it carries two extra ways to fail silently that the others do not. Both defaults, with their rationale:

| Trade-off | Default | Rationale |
|---|---|---|
| `Header always set` vs `Header set` | **`always set`** | `Header set` only applies to successful responses (2xx), so 404/500 error pages lose every protection — and error pages are HTML the browser will render just the same, so they can be framed and sniffed. Cost: it also applies to 3xx/4xx/5xx; if the application sets a header of the same name, the values must be kept consistent |
| Whether to guard with `<IfModule mod_headers.c>` | **guard added** | With `mod_headers` not loaded, the missing guard makes the whole directory **500** (an unknown directive in `.htaccess` is a fatal error), whereas with the guard it degrades to silently having no effect. Availability wins here — at the cost of a silent failure, which is why you **must** re-verify with `verify` after deploying |

```bash
# The artifact lands at the root of the publish directory (.htaccess must sit next to index.html to apply site-wide)
node src/index.mjs generate --policy headers.policy.json --out dist --only htaccess
node src/index.mjs simulate --config dist/.htaccess --policy headers.policy.json

# Reverse import: take over an existing .htaccess (hand-written files work too — Header set/unset, onsuccess and single quotes are all supported)
node src/index.mjs import --from /var/www/html/.htaccess --out headers.policy.json --force
```

## Reverse import: taking over a project that already has header config

You do not have to rewrite the policy from scratch. When you already have a `_headers` / `vercel.json` / nginx fragment / Caddyfile / Apache `.htaccess`:

```bash
$ node src/index.mjs import --from public/_headers

📥 反向导入：public/_headers
   识别格式：headers
   解析出 2 个响应头

   X-Frame-Options: SAMEORIGIN
   X-Content-Type-Options: nosniff

⚠️ 需要注意：
   · X-Frame-Options 出现了多个取值（路径 /api/*）：保留后出现的「SAMEORIGIN」，丢弃「DENY」

🛑 现状与安全基线有 3 处差距 —— 这份策略忠实反映了现状，因此它不满足基线：
   · 缺少安全基线要求的响应头：Strict-Transport-Security
   · 缺少安全基线要求的响应头：Content-Security-Policy
   · 缺少安全基线要求的响应头：Referrer-Policy

   ⚠️ 导入不会替你补齐这些 —— 补齐意味着站点"看起来合规"但实际没这些头。
```

> Output in English: `reverse import: public/_headers` / `detected format: headers` / `parsed 2 response
> headers` … `warning: X-Frame-Options has multiple values (path /api/*): keeping the later SAMEORIGIN,
> discarding DENY` … `the current state is 3 steps away from the security baseline — this policy
> faithfully reflects the current state, therefore it does not satisfy the baseline:` / `missing
> response header required by the security baseline: …` / `⚠️ the import will not fill these in for you —
> filling them in would mean the site "looks compliant" while not actually having those headers.`

Exit code **1** (same as `verify`, so it can serve as a CI gate).

**Four deliberate design decisions**:

1. **Reflect reality faithfully; do not quietly fill gaps.** An imported policy may not satisfy the security baseline — that gap is exactly what you are meant to see.
   If the import auto-filled the missing headers, you would believe the site already has that protection, which is the most dangerous way to fail.
2. **Import security response headers only, by default** (see below).
3. **Lines that cannot be parsed are not silently dropped**; they all land in `skipped` and are listed in the output.
4. **Only "name and value" can be recovered.** `severity` and `why` are human judgements and that information is simply not in a config file, so the import supplies placeholder values marked "not yet human-confirmed".

### Why `Cache-Control`-style headers are not imported by default

This one was not decided on a hunch. It came from scraping **9 real `_headers` files from public repositories** (the corpus and its sources are in [`fixtures/real-world/SOURCES.md`](fixtures/real-world/SOURCES.md)):

**In real configs, `Cache-Control` almost always takes a different value per path** — 4 of the 9 do this, and the largest has 14 path blocks:

```
/*
  Cache-Control: public, max-age=0, must-revalidate
/fonts/*
  Cache-Control: public, max-age=31536000, immutable
/img/*
  Cache-Control: public, max-age=86400, immutable
```

But the policy model is "one header, one value". A full import would flatten those three into one, and the moment a user runs "import → rename → generate → publish" they would **replace the other party's entire caching strategy with a single rule** and break live caching outright.

The root cause is a category error: `Cache-Control` / `Content-Type` / `Access-Control-*` are not security response headers and this tool has no business taking them over. Hence:

- **By default** only security-class headers are imported and the rest are explicitly reported as "not taken over" (not quietly dropped)
- Path conflicts among non-security headers **produce no warning** — we do not import them at all, and reporting conflicts would only drown out the real problems
- A file containing only non-security headers fails with an explicit error and points at the `--all` way out
- A genuine full import is available via `--all`, in which case conflicts are reported as they are

`SECURITY_HEADERS` is an explicit list. The real-corpus test suite contains a meta-test asserting that **every header appearing in the corpus is either on the list or on the deliberately-excluded list** — no "never considered it" escapees allowed.

### Acceptance criterion: round-trip consistency

A config produced by `generate` must, when run back through `import`, yield **the same set of names and values**.
nginx and caddy escape `"` inside values as `\"`, and the import must restore that correctly — otherwise "taking over someone else's project" would silently start corrupting the config from the very first generation. This invariant is enforced by a script:

```bash
$ npm run roundtrip

🔄 往返一致性检查（策略：headers.policy.json）
   原始策略有 7 个响应头

✅ cloudflare-pages   headers  7/7 个头部往返一致
✅ netlify            headers  7/7 个头部往返一致
✅ vercel             vercel   7/7 个头部往返一致
✅ nginx              nginx    7/7 个头部往返一致
✅ caddy              caddy    7/7 个头部往返一致
✅ htaccess           htaccess 7/7 个头部往返一致
```

(`round-trip consistency check (policy: headers.policy.json)` / `the original policy has 7 response headers` /
`✓ <platform>: 7/7 headers round-trip consistently`.)

CI runs it every time — breaking the escaping on either side, generator or parser, turns the build red on the spot.

### Verified against a real site

Not just passing in the simulator. A full loop was run against this site's own live `_headers`:

```bash
node src/index.mjs import --from ../Frank2673.github.io/_headers --out headers.policy.json   # import the live config
node src/index.mjs generate --policy headers.policy.json --out dist                           # regenerate
```

**Result: the generated `_headers` is byte-for-byte identical to the one being served live.**
That is, the path `import → rename → generate → publish` is equivalent to the current live state — the reverse import lost nothing, and `generate` is deterministic.

(This comparison incidentally caught a real bug: Cloudflare Pages and Netlify both emit `_headers`,
and they were originally written to the same path, so **whichever was written last won**. The comment
block in the live file therefore depended on generator iteration order. Now `planOutputPaths()` decides
the landing spots explicitly — the second artifact of the same name goes into its own subdirectory — and
CI carries an assertion that "the five landing spots are pairwise distinct".)

## CSP advisor: strict, without breaking the site

CSP is the response header most likely to break a site the moment you configure it. This project's approach is to **analyse what the page actually needs first, and only then produce a policy**:

```bash
$ node src/index.mjs advise --html index.html

内联脚本 1 段 · 内联事件 0 处 · 内联样式 0 段 · style 属性 0 处
建议的 CSP：
  default-src 'self'; script-src 'self' 'sha256-ab1dsL2WBfLFbNhNPNbdT9zQ5o8/OlH88pYN4AqLL9k='; ...
```

(`1 inline script · 0 inline event handlers · 0 inline style blocks · 0 style attributes` / `suggested CSP:`)

**Key design: for inline scripts on the page it computes a SHA-256 hash automatically and uses `'sha256-...'` instead of `'unsafe-inline'`.**
(A flash-preventing theme script has to be inline, but allowing it by hash keeps the policy strict without sacrificing the experience.)

It is also honest about the risks:

- The page has inline event attributes (`onclick`) → the hash is useless, only `unsafe-inline` can allow it, and switching to `addEventListener` is recommended
- Third-party script origins detected → listed explicitly
- It recommends starting with `Content-Security-Policy-Report-Only` to observe

### Hash drift detection

The cost of the hash approach is "change the script and you must change the policy". The tool catches that trap for you:

```bash
$ node src/index.mjs advise --html index.html --check headers.policy.json
❌ 策略中残留了页面上已不存在的 hash（脚本已改动，策略过期）
   → 请重新运行 advise 并更新策略中的 CSP
```

(`❌ the policy still contains a hash that no longer exists on the page (the script changed, the policy
is stale)` / `→ re-run advise and update the CSP in the policy`.)

Put it in CI and you stop "changed the inline script but forgot to update the CSP" on the very day it happens.

## Shipping to Cloudflare (dry-run by default + snapshot rollback)

The generated `_headers` has to be deployed before it takes effect. If you want the policy to reach production **without manual copy-paste**, use `src/deploy/cloudflare.mjs` (also zero-dependency):

```bash
# ① Check the token (read-only, changes nothing)
$ node src/deploy/cloudflare.mjs --verify-token
  令牌：cf*** (sha256:b303814744da) · 长度 45 · 格式 scannable
✅ 令牌有效（status=active）。

# ② Rehearse: print every request that would be sent, send none (default behaviour)
$ node src/deploy/cloudflare.mjs --zone <zone-id or domain>

# ③ Really ship it: GET the current state into a snapshot first, then PUT over it
$ node src/deploy/cloudflare.mjs --zone <zone-id or domain> --apply
  📸 变更前快照：tmp/cloudflare-deploy/cf-ruleset-before-2026-09-25T04-10-36-664Z.json
  ✅ 下发完成。规则：2 条 → 3 条
  回滚命令：node src/deploy/cloudflare.mjs --zone <zone-id> --rollback "…" --apply
```

(`token: cf*** (sha256:…) · length 45 · format scannable` / `✓ token valid (status=active)` /
`📸 pre-change snapshot: …` / `✓ deployment complete. rules: 2 → 3` / `rollback command: …`)

Four hard rules, each one forced by a real failure:

| Rule | Why |
|---|---|
| **Dry-run by default**, only `--apply` really sends | The cost of a copy-paste mistake is a **silent degradation** of live protection that is only discovered in the next verification round |
| **Always snapshot before writing**, `--rollback` restores in one command | A full overwrite without a snapshot is unrecoverable |
| **Only replace rules prefixed `header-forge:`** | That phase's entrypoint may contain rules other people created; a full overwrite deletes them with no warning at all |
| **The token is only read from `CLOUDFLARE_API_TOKEN`** | Command-line arguments end up in shell history and the process list; output keeps only the first 2 characters plus a short sha256 hash, and nothing is ever written to disk |

How to configure token permissions, what `9106` / `6111` / `10000` / `403` mean, and how to roll back — see **[docs/cloudflare-deploy.md](docs/cloudflare-deploy.md)**.

## Command-line reference

| Subcommand | Purpose | Exit codes |
|---|---|---|
| `generate` | Generate per-platform config from a policy | 0 success / 2 error |
| `import` | Reverse-import an existing config into a policy draft | 0 success / **1 current state non-compliant** / 2 error |
| `verify` | Check whether live response headers match the policy | 0 match / 1 mismatch / 2 error |
| `advise` | Analyse a page and suggest a CSP | 0 success / 1 hash drift / 2 error |
| `simulate` | Serve the generated config locally and self-verify | 0 match / 1 mismatch / 2 error |

> Shipping Cloudflare Transform Rules is a **separate script** (not an `index.mjs` subcommand):
> `node src/deploy/cloudflare.mjs --zone <zone-id|domain>` — dry-run by default, `--apply` to really send.
> See [docs/cloudflare-deploy.md](docs/cloudflare-deploy.md).

Common options: `--policy <path>`, `--out <dir/file>`; subcommands add `--url`, `--html`, `--config`, `--only`, `--port`, `--check`, `--from`, `--format`, `--force`, `--stdout`.
Full reference: `node src/index.mjs --help`

## Using it in your own repository

```yaml
name: security response headers
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 3 * * 1'

jobs:
  headers:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }

      # 1. Changed an inline script but forgot to update the CSP hash → blocked
      - name: 检查 CSP hash 是否漂移
        run: node src/index.mjs advise --html index.html --check headers.policy.json

      # 2. The generated config must still satisfy the policy (offline self-proof)
      - name: 生成配置并本地自证
        run: |
          node src/index.mjs generate --policy headers.policy.json --out dist
          node src/index.mjs simulate --config dist/_headers --policy headers.policy.json

      # 3. The live response headers must match the policy (regression guard)
      - name: 线上一致性校验
        run: node src/index.mjs verify --policy headers.policy.json
```

Step 3 is the most valuable line of defence: **the moment anyone changes a deployment config and degrades protection, CI turns red that same day.**

## Design decisions

| Decision | Rationale |
|---|---|
| **Zero dependencies** | Only Node built-in modules (`crypto`/`https`/`http`), no `npm install` in CI, zero supply-chain surface |
| **`unsafe-inline` rejected (script-src)** | Policy validation refuses it outright; if you genuinely need it you must switch to a hash or explain it in `why` |
| **Config-injection protection** | Policy values are rendered into nginx/caddy syntax, so values containing newlines or tabs are always rejected (otherwise a single newline injects arbitrary directives) |
| **`.htaccess` defaults to `always set` + `<IfModule>` guard** | Error responses need protection too (`Header set` only covers 2xx); without the guard, a missing `mod_headers` would 500 the whole site. The cost is that failures are silent, which is why `verify` is required after deployment |
| **Validation allows "stronger"** | A larger HSTS `max-age` or a CSP with extra directives still passes — otherwise the tool would cry wolf daily and eventually nobody would look |
| **The simulator parses the real artifact** | Validating the policy object alone would be self-deception; what must be validated is "the thing that was generated" |
| **Validate response integrity** | Carrying over a lesson from surface-watch: a truncated response from an interrupted connection must be treated as a failure, otherwise it yields the wrong conclusion that "the header is missing" |

## Limitations

- The generated config only takes effect **once you deploy it to the corresponding platform**; this tool does not deploy for you
- `verify` validates "the response headers of a single URL"; if the site sets different headers per path, each path needs its own check
- Reverse import **can only recover "name and value"**: `severity`/`why` are human judgements and are not in the config; the policy model allows only one value per header, so multi-path blocks or multiple `source` rules are merged (with a warning when merging)
- Structural information such as nginx `location` nesting or Caddy matchers cannot be expressed in the policy model; an import only reflects "which headers the file declares"
- Apache `.htaccess` is **file-level** configuration and carries two extra silent-failure points: the site must already have `mod_headers` loaded, and overrides must be permitted (the main config needs `AllowOverride FileInfo` — the Override class for the `Header` directive), otherwise the whole block has no effect and usually reports no error. The simulator can prove "the values and structure in the artifact are correct" but **cannot verify whether your Apache really loaded the module or permits overrides** — measure the live site with `verify` after deploying
- `.htaccess` has no path patterns: it applies as a whole to its directory and its subdirectories. To set different headers per path you must place artifacts into the respective directories (one per directory); the policy model's "one value per header" cannot express that difference
- `Header always unset Server` does not take effect under some configurations (`Server` is generated by core); the more reliable route is `ServerTokens` / `ServerSignature` in the main config — which is main-config territory and outside what this tool can generate
- The CSP advisor analyses static HTML: scripts loaded at runtime, dynamically created iframes and the like cannot be foreseen, so starting with Report-Only is still recommended
- It does not handle DNS-layer issues (such as DMARC records) — that is surface-watch's domain, and it requires a domain of your own

## Roadmap

- [x] Read existing `_headers` / `vercel.json` / nginx / Caddyfile for **reverse import** (including the round-trip consistency guard)
- [x] Ship directly via the Cloudflare Transform Rules API (no more manual copy-paste) — dry-run by default, snapshot before writing, one-command rollback ([docs/cloudflare-deploy.md](docs/cloudflare-deploy.md))
- [ ] Add `--paths` to verify multiple URLs in one run
- [ ] Emit SARIF, integrated with GitHub Code Scanning
- [x] Add an Apache `.htaccess` generator (including reverse import)

## License

[MIT](LICENSE) © 2026 Frank2673
