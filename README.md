# header-forge

[English](README.en.md) | 简体中文

[![CI](https://github.com/Frank2673/header-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/Frank2673/header-forge/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![零依赖](https://img.shields.io/badge/运行时依赖-0-brightgreen)
![测试](https://img.shields.io/badge/测试-204%20passed-brightgreen)

**安全响应头配置即代码** —— 一次声明，多平台生成，线上校验，本地可证。
支持从现有配置**反向导入**（接管别人的项目），并以往返一致性守卫保证生成与解析严格对称。

> 配套项目：[surface-watch](https://github.com/Frank2673/surface-watch)（发现问题）→ **header-forge**（修掉问题并防止回退）

---

## 它解决的真实问题

用 surface-watch 扫描自己的站点，得到 6 条响应头缺失：

```
❌ 缺少 Content-Security-Policy        ❌ 缺少 X-Frame-Options
❌ 缺少 X-Content-Type-Options         ❌ 缺少 Referrer-Policy
❌ 缺少 Permissions-Policy             ⚠️ HSTS 缺 includeSubDomains
```

但**发现问题和修掉问题之间隔着一条鸿沟**：站点托管在 GitHub Pages 上，而 **GitHub Pages 不支持自定义响应头**。

于是有了这个项目。它不假装问题不存在，而是把「修复」拆成三件可验证的事：

| 环节 | 做法 | 产物 |
|---|---|---|
| **声明** | 策略即代码，带严重度与理由 | `headers.policy.json` |
| **落地** | 生成 6 种平台的原生配置 | `_headers` / `vercel.json` / nginx / caddy / `.htaccess` |
| **验证** | 线上一致性校验 + 本地模拟自证 | 一致性报告 / CI 门禁 |

## 最值得说的一点：本地可证

「配置写了但没生效」是这类工作最常见的翻车方式。所以本项目内置**模拟器**：

```
策略 → 生成器 → 配置文件（真实产物） → 解析并应用到 HTTP 响应 → 校验器 → ✅ 100% 一致
```

```bash
$ node src/index.mjs generate --policy headers.policy.json --out dist
$ node src/index.mjs simulate --config dist/_headers --policy headers.policy.json

🧪 用 _headers 启动本地模拟服务…
   从配置中解析出 7 个响应头
✅ 完全符合策略 | 符合 7 | 缺失 0 | 值不符 0
```

关键在于模拟器**解析的是生成出来的配置文件本身**，而不是复用策略对象 —— 生成器任何一处写错、漏写、转义错误都会在这里暴露。**不需要买域名、不需要部署，就能证明配置有效。**

## 快速开始

零依赖，无需 `npm install`（Node ≥ 20）：

```bash
# 1. 生成各平台配置
node src/index.mjs generate --policy headers.policy.json --out dist

# 2. 本地自证：生成的配置确实能达到策略
node src/index.mjs simulate --config dist/_headers --policy headers.policy.json

# 3. 校验线上实际响应头（CI 门禁：不一致则退出码 1）
node src/index.mjs verify --policy headers.policy.json

# 4. 为页面生成不会打坏站点的 CSP（含内联脚本 hash）
node src/index.mjs advise --html path/to/index.html
```

## 生成器矩阵

| 平台 | 产物 | 说明 |
|---|---|---|
| **Cloudflare Pages** | `_headers` | 免费套餐支持，**无需自有域名**（可用 `*.pages.dev`） |
| **Netlify** | `_headers` | 免费套餐支持；路径匹配比 Cloudflare 严格 |
| **Vercel** | `vercel.json` | 同时输出可合并的片段，避免覆盖已有配置 |
| **Nginx** | `add_header` 指令 | 提示 `add_header` 的继承陷阱；值做转义防配置注入 |
| **Caddy** | `Caddyfile` 片段 | 支持 `-HeaderName` 直接删除响应头 |
| **Apache** | `.htaccess` | `mod_headers` + `<IfModule>` 守卫；前置条件（`AllowOverride FileInfo`）写在产物注释与下方局限里 |

> GitHub Pages 不在此列 —— 因为它**不支持**自定义响应头。迁移路径见 [MIGRATION.md](MIGRATION.md)。

### Apache `.htaccess`：两个默认取舍

它是唯一一个**文件级**产物，所以比别人多了两个"不生效是无声的"风险点，两处的默认选择与理由：

| 取舍 | 默认 | 理由 |
|---|---|---|
| `Header always set` vs `Header set` | **`always set`** | `Header set` 只作用于成功响应（2xx），404/500 错误页会丢掉全部防护 —— 而错误页同样是浏览器会渲染的 HTML，可以被打框架、被嗅探。代价：也会作用于 3xx/4xx/5xx；若应用自己设置同名头，需保持取值一致 |
| 是否用 `<IfModule mod_headers.c>` 守卫 | **加守卫** | mod_headers 未加载时，没有守卫会让整个目录 **500**（.htaccess 的未知指令是致命错误），有守卫则退化为静默不生效。选可用性优先 —— 代价是失败无声，所以部署后**必须**用 `verify` 复验 |

```bash
# 产物落在发布目录根下（.htaccess 必须与 index.html 同级才对整个站点生效）
node src/index.mjs generate --policy headers.policy.json --out dist --only htaccess
node src/index.mjs simulate --config dist/.htaccess --policy headers.policy.json

# 反向导入：接管已有的 .htaccess（手写文件也认 —— Header set/unset、onsuccess、单引号都支持）
node src/index.mjs import --from /var/www/html/.htaccess --out headers.policy.json --force
```

## 反向导入：接管一个已经有响应头配置的项目

不用从零重写策略。手上已经有一份 `_headers` / `vercel.json` / nginx 片段 / Caddyfile / Apache `.htaccess` 时：

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

退出码 **1**（与 `verify` 一致，可作 CI 门禁）。

**四条刻意的设计决定**：

1. **忠实反映现状，不顺手补齐**。导入出来的策略可能不满足安全基线 —— 那正是要给你看的差距。
   如果导入时自动补上缺失的头，你会以为站点已经有这些防护，这是最危险的失败方式。
2. **默认只接管安全响应头**（见下）。
3. **解析不了的行不静默丢弃**，都进 `skipped` 并在输出里列出来。
4. **只恢复得回"名字与取值"**。`severity` 与 `why` 是人的判断，配置里没有这些信息，
   导入时给占位值并标注"尚未人工确认"。

### 为什么默认不导入 `Cache-Control` 这类头

这一条不是拍脑袋定的，是抓了 **9 份公开仓库的真实 `_headers`** 之后改的
（语料与出处见 [`fixtures/real-world/SOURCES.md`](fixtures/real-world/SOURCES.md)）：

**真实配置里 `Cache-Control` 几乎总是按路径分别取值** —— 9 份里有 4 份，最多一份有 14 个路径块：

```
/*
  Cache-Control: public, max-age=0, must-revalidate
/fonts/*
  Cache-Control: public, max-age=31536000, immutable
/img/*
  Cache-Control: public, max-age=86400, immutable
```

而策略模型是「一个头一个取值」。全量导入会把这三条压平成一条，
用户一旦"导入 → 改名 → generate → 发布"，就会**用一条规则替换掉对方整套缓存策略**，
直接搞坏线上缓存。

根因是分类错误：`Cache-Control` / `Content-Type` / `Access-Control-*` 不是安全响应头，
本工具不该接管它们。所以：

- **默认**只导入安全类，其余明确报告为"未接管"（不是悄悄丢掉）
- 非安全头的按路径冲突**不产生警告** —— 我们根本不导入它们，报冲突只会淹没真正的问题
- 文件里只有非安全头时明确报错，并提示 `--all` 的出路
- 确实要全量导入用 `--all`，此时冲突会如实报出来

`SECURITY_HEADERS` 是一份显式清单。真实语料测试里有一条元测试：
**语料中出现的每一个头，要么在清单里、要么在"刻意排除"清单里** ——
不允许有"没考虑过"的漏网。

### 验收标准：往返一致

`generate` 出来的配置，`import` 回去必须得到**同一组名字与取值**。
nginx / caddy 会把值里的 `"` 转义成 `\"`，导入时必须正确还原 —— 否则"接管别人项目"
会从第一次生成就开始悄悄改坏配置。这条不变式由脚本强制：

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

CI 每次都会跑它 —— 生成器或解析器任何一侧改坏转义，都会当场红。

### 已对真实站点验证过

不只是模拟器里跑通。用本站点自己的线上 `_headers` 做过一次完整闭环：

```bash
node src/index.mjs import --from ../Frank2673.github.io/_headers --out headers.policy.json   # 导入线上配置
node src/index.mjs generate --policy headers.policy.json --out dist                           # 重新生成
```

**结果：生成的 `_headers` 与线上正在服务的那一份逐字节完全一致。**
即 `import → 改名 → generate → 发布` 这条路径与当前线上状态等价 ——
反向导入没有丢失任何东西，`generate` 也是确定性的。

（这次比对顺带抓出一个真 bug：Cloudflare Pages 与 Netlify 都输出 `_headers`，
原来会写进同一个路径，**谁后写谁生效**。线上那份的注释块因此取决于生成器遍历顺序。
现在 `planOutputPaths()` 显式决定落点：第二份同名产物进自己的子目录，
CI 里有一条断言"五个落点两两不同"。）

## CSP 顾问：既严格，又不打坏站点

CSP 是最容易「配了就坏站」的响应头。本项目的做法是**先分析页面真实需求，再给策略**：

```bash
$ node src/index.mjs advise --html index.html

内联脚本 1 段 · 内联事件 0 处 · 内联样式 0 段 · style 属性 0 处
建议的 CSP：
  default-src 'self'; script-src 'self' 'sha256-ab1dsL2WBfLFbNhNPNbdT9zQ5o8/OlH88pYN4AqLL9k='; ...
```

**关键设计：对页面里的内联脚本自动计算 SHA-256 hash，用 `'sha256-...'` 代替 `'unsafe-inline'`。**
（防闪烁的主题脚本必须内联，但用 hash 放行既保留严格策略、又不牺牲体验。）

同时它会诚实地提示风险：

- 页面有内联事件属性（`onclick`）→ hash 无效，只能放行 `unsafe-inline`，并建议改用 `addEventListener`
- 检测到第三方脚本来源 → 明确列出
- 建议先用 `Content-Security-Policy-Report-Only` 观察

### hash 漂移检测

hash 方案的代价是"改了脚本就得改策略"。这个坑由工具自己兜住：

```bash
$ node src/index.mjs advise --html index.html --check headers.policy.json
❌ 策略中残留了页面上已不存在的 hash（脚本已改动，策略过期）
   → 请重新运行 advise 并更新策略中的 CSP
```

放进 CI，就能在「改了内联脚本忘了更新 CSP」的当天拦住它。

## 下发到 Cloudflare（dry-run 默认 + 快照回滚）

生成的 `_headers` 要生效得先部署。如果你想让策略**绕过手工粘贴**直接落到线上，
可以用 `src/deploy/cloudflare.mjs`（同样零依赖）：

```bash
# ① 自检令牌（只读，不改任何东西）
$ node src/deploy/cloudflare.mjs --verify-token
  令牌：cf*** (sha256:b303814744da) · 长度 45 · 格式 scannable
✅ 令牌有效（status=active）。

# ② 预演：打印将要发出的每个请求，一个都不发（默认行为）
$ node src/deploy/cloudflare.mjs --zone <zone-id 或域名>

# ③ 真下发：先 GET 现状存快照，再 PUT 覆盖
$ node src/deploy/cloudflare.mjs --zone <zone-id 或域名> --apply
  📸 变更前快照：tmp/cloudflare-deploy/cf-ruleset-before-2026-09-25T04-10-36-664Z.json
  ✅ 下发完成。规则：2 条 → 3 条
  回滚命令：node src/deploy/cloudflare.mjs --zone <zone-id> --rollback "…" --apply
```

四条硬规则，每一条都是被真实故障逼出来的：

| 规则 | 原因 |
|---|---|
| **默认 dry-run**，`--apply` 才真发 | 手工粘贴翻车的代价是线上防护**静默降级**，要等下一轮校验才发现 |
| **写前必存快照**，`--rollback` 一键还原 | 没有快照的一次全量覆盖是不可回滚的 |
| **只替换 `header-forge:` 前缀的规则** | 这个 phase 的 entrypoint 里可能还有别人建的规则；全量覆盖 = 删掉它们，且没有任何提示 |
| **令牌只从 `CLOUDFLARE_API_TOKEN` 读** | 命令行传参会进 shell 历史与进程列表；输出只留前 2 位 + sha256 短哈希，永不落盘 |

令牌权限怎么配、`9106` / `6111` / `10000` / `403` 分别是什么意思、怎么回滚，
见 **[docs/cloudflare-deploy.md](docs/cloudflare-deploy.md)**。

## 命令行参考

| 子命令 | 作用 | 退出码 |
|---|---|---|
| `generate` | 用策略生成各平台配置 | 0 成功 / 2 错误 |
| `import` | 从现有配置反向导入，生成策略草稿 | 0 成功 / **1 现状不合规** / 2 错误 |
| `verify` | 校验线上响应头是否与策略一致 | 0 一致 / 1 不一致 / 2 错误 |
| `advise` | 分析页面并给出 CSP 建议 | 0 成功 / 1 hash 漂移 / 2 错误 |
| `simulate` | 用生成的配置起服务并自校验 | 0 一致 / 1 不一致 / 2 错误 |

> Cloudflare Transform Rules 的下发是**独立脚本**（不是 `index.mjs` 的子命令）：
> `node src/deploy/cloudflare.mjs --zone <zone-id|域名>` —— 默认 dry-run，`--apply` 才真发。
> 见 [docs/cloudflare-deploy.md](docs/cloudflare-deploy.md)。

通用参数：`--policy <路径>`、`--out <目录/文件>`；各子命令另有 `--url`、`--paths`、`--sarif`、`--html`、`--config`、`--only`、`--port`、`--check`、`--from`、`--format`、`--force`、`--stdout`。
完整说明：`node src/index.mjs --help`

### 一次校验多个地址（`--paths`）

只校验 `/` 会得出"站点已合规"的错误结论 —— 真实站点经常是根路径一套、后台/API/下载路径另一套。
`verify --paths` 逐条校验并给出汇总：

```bash
# 逗号分隔（也接受换行分隔）
node src/index.mjs verify --url https://example.com --paths /,/admin,/api/v1

# 空行与 # 注释会被忽略，适合把清单签进仓库
node src/index.mjs verify --url https://example.com --paths @paths.txt

# 完整 URL 原样使用，不受基准地址影响（两种写法可混用）
node src/index.mjs verify --paths @paths.txt,https://other.example/x
```

- `--url` 在批量模式下只作为**基准地址**（相对路径拼到它之后），不再单独校验一次；不给基准时相对路径会直接报错（退出码 2），而不是猜一个地址
- 输出：逐条结果（一致 / 不一致 + 缺哪个头 / 拉取失败）+ 一行汇总
- **退出码**：`0` 全部一致 · `1` 存在不一致 · `2` 参数或运行错误（含任一地址拉取失败）
- 拉取失败**不算"不一致"**：拿不到响应时我们并不知道合规不合规，报 1 会把"没测到"说成"测出来不合规"
- 串行执行：报告顺序与输入顺序一致（可复现），也避免把对方站点打出限流

### 输出 SARIF（接入 GitHub Code Scanning）

`verify` 加 `--sarif <路径>` 会额外产出一份 SARIF 2.1.0，可直接上传到 Code Scanning：

```bash
node src/index.mjs verify --policy headers.policy.json --out out --sarif out/results.sarif
```

```yaml
permissions:
  contents: read
  security-events: write   # 上传 SARIF 需要

steps:
  - run: node src/index.mjs verify --policy headers.policy.json --out out --sarif out/results.sarif
    continue-on-error: true          # 先让 SARIF 落盘，再由下一步上传
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: out/results.sarif
      category: header-forge
```

设计取舍（每一条都直接影响面板好不好用）：

| 决策 | 具体做法 | 原因 |
|---|---|---|
| 哪些问题上报 | 只报 `missing`（策略要求但线上没有）与 `mismatch`（取值被放宽） | `extra` 头是"策略未声明"而不是违规，而站点几乎总有 `Server`/`X-Powered-By` 这类头 —— 报进去就是永远关不掉的噪音；拉取失败属于"没测到"，由退出码 2 表达，不该在面板里伪装成安全告警。两者都保留在 JSON/Markdown 报告与 SARIF 的 `run.properties` 里 |
| level 映射 | `critical`/`high` → `error`，`medium` → `warning`，`low`/`info` → `note` | 与策略里声明的 severity 一致 —— 只改 `headers.policy.json` 就能改变面板上的分级 |
| `ruleId` 命名 | `header-forge/<状态>/<头名>`，例 `header-forge/missing/referrer-policy`，**不含 URL** | 含 URL 的话同一类问题在 10 个路径上就是 10 条规则，面板会被刷爆；`missing` 与 `mismatch` 是两类问题，分开才能分别统计 |
| `partialFingerprints` | `sha256(状态 \| URL \| 头名)`，**不含实际值、期望值、时间戳** | 这是去重键：站点把 `max-age` 从 600 改成 300 时问题仍是"同一个问题"，指纹必须不变 —— 否则每跑一次 CI 就新开一条告警，旧的那条永远悬着 |
| 告警位置 | 指向策略文件（`artifactLocation.uri` = `--policy` 的值），URL 保留在 `message`／`properties` | 远端 URL 不是仓库内文件；要修的是策略或部署配置，落在策略文件上最接近"该改哪儿" |

写完会当场自检：JSON 可解析、必填字段与 `level`/`ruleId`/指纹齐全、**结果数 = 输入问题数**；
自检不过退出码 2（不交出未经校验的扫描结果）。

## 用在你自己的仓库里

```yaml
name: 安全响应头
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

      # 1. 改了内联脚本却忘了更新 CSP hash → 拦住
      - name: 检查 CSP hash 是否漂移
        run: node src/index.mjs advise --html index.html --check headers.policy.json

      # 2. 生成的配置必须仍能满足策略（离线自证）
      - name: 生成配置并本地自证
        run: |
          node src/index.mjs generate --policy headers.policy.json --out dist
          node src/index.mjs simulate --config dist/_headers --policy headers.policy.json

      # 3. 线上实际响应头必须与策略一致（防回退）
      - name: 线上一致性校验
        run: node src/index.mjs verify --policy headers.policy.json
```

第 3 步是最有价值的一道防线：**任何人改掉部署配置导致防护降级，CI 当天就会红。**

## 设计决策

| 决策 | 原因 |
|---|---|
| **零依赖** | 只用 Node 内置模块（`crypto`/`https`/`http`），CI 里无需 `npm install`，供应链面为零 |
| **拒绝 `unsafe-inline`（script-src）** | 策略校验会直接拒绝它；确需放行必须改用 hash 或在 `why` 中明确说明 |
| **配置注入防护覆盖每一个渲染字段** | 策略值会被渲染进 nginx/caddy 语法，含换行/制表符的值一律拒绝；`remove` 的名字同样会进配置语法（caddy 的 `-Name` 是裸渲染），所以它必须过与头部名同源的 RFC 7230 token 校验 —— 曾经漏了这一处，一个带换行的 `remove` 就能注入任意指令（策略层 + 生成器各一道，缺一不可） |
| **`.htaccess` 默认 `always set` + `<IfModule>` 守卫** | 错误响应也要有防护（`Header set` 只覆盖 2xx）；缺 mod_headers 时没守卫会让整站 500。代价是"不生效不报错"，所以要求部署后用 `verify` 复验 |
| **校验允许"更强"** | HSTS 的 max-age 更大、CSP 有额外指令都算通过 —— 否则工具天天误报，最后没人看 |
| **模拟器解析真实产物** | 只验证策略对象是自欺欺人；必须验证"生成出来的东西" |
| **校验响应完整性** | 沿用 surface-watch 的教训：被中断的残缺响应必须判为失败，否则会得出"头部缺失"的错误结论 |

## 局限

- 生成的配置需要**由你部署到对应平台**才会生效；本工具不替你部署
- `verify` 默认校验**单个 URL**；要覆盖按路径分别设置的头，用 `--paths`（批量形态）把路径列全 —— 工具不会替你去发现有哪些路径，`paths.txt` 需要你自己维护
- 反向导入**只能恢复"名字与取值"**：`severity`/`why` 是人的判断，配置里没有；策略模型一个头只有一个取值，多路径块或多条 `source` 规则会被合并（合并时给出警告）
- nginx 的 `location` 嵌套、Caddy 的匹配器等结构信息在策略模型里表达不了，导入时只反映"文件里写了哪些头"
- Apache `.htaccess` 是**文件级**配置，多两个静默失效点：需要站点已加载 `mod_headers`，且允许覆盖（主配置 `AllowOverride FileInfo` —— `Header` 指令的 Override 类别），否则整块配置不生效、通常也不报错。模拟器能证明"产物里的取值与结构正确"，但**验证不了你的 Apache 是否真的加载了模块、是否允许覆盖** —— 部署后请用 `verify` 对线上实测
- `.htaccess` 没有路径模式：它整块作用于所在目录及其子目录。要按路径设置不同的头，得把产物分别放进对应目录（每目录一份），策略模型里"一个头一个取值"表达不了这种差异
- `Header always unset Server` 在部分配置下不生效（`Server` 由 core 生成），更可靠的是主配置里的 `ServerTokens` / `ServerSignature` —— 那属于主配置，本工具生成不了
- CSP 顾问基于静态 HTML 分析：运行时才加载的脚本、动态创建的 iframe 等无法预知，仍建议先上 Report-Only
- 不处理 DNS 层面的问题（如 DMARC 记录）—— 那是 surface-watch 的领域，且需要自有域名
- `--paths` 批量校验是**串行**的：地址很多时慢，也没有并发上限控制（取舍是报告顺序可复现、且不会给对方站点造成突发并发）
- SARIF 里的告警位置固定指向策略文件：GitHub Code Scanning 需要"仓库内的位置"，而响应头不符的根因可能在部署配置（`_headers` / nginx / CDN 控制台）—— 面板上的文件位置只是入口，`message` 里带了具体 URL
- SARIF 只上报 `missing` 与 `mismatch`：`extra` 头与"拉取失败"不进面板（理由见上文表格），它们只在报告与 `run.properties` 里
- 本仓库的 CI 目前**没有**把 `--sarif` 接进自己的工作流（`verify` 仍按退出码门禁）；要启用只需按上文 YAML 给 `conformance.yml` 加 `security-events: write` 与 `upload-sarif` 两步

## 路线图

- [x] 支持读取已有 `_headers` / `vercel.json` / nginx / Caddyfile 做**反向导入**（含往返一致性守卫）
- [x] 支持 Cloudflare Transform Rules API 直接下发（省去手工粘贴）—— 默认 dry-run、写前存快照、可一键回滚（[docs/cloudflare-deploy.md](docs/cloudflare-deploy.md)）
- [x] 增加 `--paths` 批量校验多个 URL（含 `@文件` 清单、汇总、退出码语义；见上文）
- [x] 输出 SARIF，接入 GitHub Code Scanning（`verify --sarif <路径>`；见上文的设计取舍表）
- [x] 增加 Apache `.htaccess` 生成器（含反向导入）

## 许可

[MIT](LICENSE) © 2026 Frank2673
