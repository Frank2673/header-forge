# header-forge

[![CI](https://github.com/Frank2673/header-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/Frank2673/header-forge/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**安全响应头配置即代码** —— 一次声明，多平台生成，线上校验，本地可证。

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
| **落地** | 生成 5 种平台的原生配置 | `_headers` / `vercel.json` / nginx / caddy |
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

> GitHub Pages 不在此列 —— 因为它**不支持**自定义响应头。迁移路径见 [MIGRATION.md](MIGRATION.md)。

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

## 命令行参考

| 子命令 | 作用 | 退出码 |
|---|---|---|
| `generate` | 用策略生成各平台配置 | 0 成功 / 2 错误 |
| `verify` | 校验线上响应头是否与策略一致 | 0 一致 / 1 不一致 / 2 错误 |
| `advise` | 分析页面并给出 CSP 建议 | 0 成功 / 1 hash 漂移 / 2 错误 |
| `simulate` | 用生成的配置起服务并自校验 | 0 一致 / 1 不一致 / 2 错误 |

通用参数：`--policy <路径>`、`--out <目录>`；各子命令另有 `--url`、`--html`、`--config`、`--only`、`--port`、`--check`。
完整说明：`node src/index.mjs --help`

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
| **配置注入防护** | 策略值会被渲染进 nginx/caddy 语法，含换行/制表符的值一律拒绝（否则一个换行就能注入任意指令） |
| **校验允许"更强"** | HSTS 的 max-age 更大、CSP 有额外指令都算通过 —— 否则工具天天误报，最后没人看 |
| **模拟器解析真实产物** | 只验证策略对象是自欺欺人；必须验证"生成出来的东西" |
| **校验响应完整性** | 沿用 surface-watch 的教训：被中断的残缺响应必须判为失败，否则会得出"头部缺失"的错误结论 |

## 局限

- 生成的配置需要**由你部署到对应平台**才会生效；本工具不替你部署
- `verify` 校验的是「单个 URL 的响应头」；若站点按路径设置不同头，需要对每个路径分别校验
- CSP 顾问基于静态 HTML 分析：运行时才加载的脚本、动态创建的 iframe 等无法预知，仍建议先上 Report-Only
- 不处理 DNS 层面的问题（如 DMARC 记录）—— 那是 surface-watch 的领域，且需要自有域名

## 路线图

- [ ] 支持 Cloudflare Transform Rules API 直接下发（省去手工粘贴）
- [ ] 增加 `--paths` 批量校验多个 URL
- [ ] 输出 SARIF，接入 GitHub Code Scanning
- [ ] 支持读取已有 `_headers` / `vercel.json` 做**反向导入**（从现状生成策略）
- [ ] 增加 Apache `.htaccess` 生成器

## 许可

[MIT](LICENSE) © 2026 Frank2673
