# 更新日志

本项目的所有重要变更都记录在此文件。

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

> **0.1.0 是本仓库的首个 tagged release。** 本条目按最终状态编写，
> 因此「新增」一节覆盖了从首个提交 `69e9471` 到本版本的全部能力，
> 而不是某一次发布的增量。文中每一节末尾标注来源，便于逐条核对。

## [Unreleased]

## [0.1.0] - 2026-09-25

**首个 tagged release。** 安全响应头配置即代码：一次声明，多平台生成，线上校验，本地可证。
支持从现有配置**反向导入**（接管别人的项目），并以往返一致性守卫保证生成与解析严格对称。

起点是一次真实失败：用 [surface-watch](https://github.com/Frank2673/surface-watch)
在自有站点扫出 6 项响应头缺失，但站点托管在 GitHub Pages 上，而 GitHub Pages
**不支持自定义响应头**。本项目把「修复」拆成三件可验证的事：声明 → 落地 → 验证。

### 新增

- **策略即代码（`headers.policy.json`、`src/lib/policy.mjs`）**
  - 一个头一条记录，带 `severity` 与 `why`（人的判断写进策略，而不是散在部署平台的控制台里）
  - 校验包含安全基线与**配置注入防护**：值含换行/制表符一律拒绝
  - 校验拆成 `collectPolicyProblems()`（返回 problems，不抛异常）与
    `validatePolicy()`（有问题就抛）—— 反向导入需要前者：从现有配置导入的策略
    本来就可能不合规，那是要展示的差距，不是一个该炸掉的错误
  - 策略支持**多目标**并标注 `primary`：Cloudflare Pages（必须符合，参与门禁）/
    GitHub Pages（平台限制，仅作对照）
  - 〔来源：commit `69e9471`（初版）+ `3046b9c`（多目标）+ `2684333`（校验拆分）
    + README「它解决的真实问题」三环节表 +「设计决策」表〕

- **六平台生成器（`src/generators/*.mjs`）**
  - **Cloudflare Pages** → `_headers`（免费套餐支持，无需自有域名）
  - **Netlify** → `_headers`（路径匹配比 Cloudflare 严格）
  - **Vercel** → `vercel.json`（同时输出可合并片段，避免覆盖已有配置）
  - **Nginx** → `add_header` 指令（提示 `add_header` 的继承陷阱；值做转义防注入）
  - **Caddy** → `Caddyfile` 片段（支持 `-HeaderName` 直接删除响应头）
  - **Apache** → `.htaccess`（`mod_headers` + `<IfModule>` 守卫；前置条件写进产物注释与局限）
  - 落点由 `planOutputPaths()` 显式决定：同名产物（Cloudflare Pages 与 Netlify 都输出
    `_headers`）不再互相覆盖，第二份进自己的子目录
  - 〔来源：commit `69e9471`（五平台）+ `8a195d4`（第六个：Apache）+ `cdd7b15`（落点决策）
    + README「生成器矩阵」表〕

- **Apache `.htaccess` 的两个默认取舍**
  - `Header always set`（而非 `Header set`）：后者只作用于 2xx，404/500 错误页会丢掉全部
    防护 —— 而错误页同样是浏览器会渲染、可被打框架的 HTML。代价是会波及 3xx/4xx/5xx
  - 加 `<IfModule mod_headers.c>` 守卫：缺 `mod_headers` 时无守卫的未知指令在 `.htaccess`
    里是致命错误，整个目录直接 500；有守卫则退化为静默不生效。选可用性优先，代价是失败无声，
    因此要求部署后用 `verify` 复验
  - 〔来源：commit `8a195d4` + README「Apache `.htaccess`：两个默认取舍」表〕

- **本地模拟器：证明「配置写了且真的生效」（`src/simulate.mjs`）**
  - 解析**生成出来的配置文件本身**（而不是复用策略对象），应用到 HTTP 响应，再用同一校验器比对
  - 生成器任何一处写错、漏写、转义错误都会在这里暴露
  - **不需要买域名、不需要部署**，就能证明配置有效
  - 〔来源：commit `69e9471` + README「最值得说的一点：本地可证」〕

- **CSP 顾问（`src/advise.mjs`）**
  - 分析页面真实资源需求后给策略；对页面里的内联脚本自动计算 **SHA-256 hash**，
    用 `'sha256-...'` 代替 `'unsafe-inline'`
  - 诚实提示风险：页面有内联事件属性（`onclick`）时 hash 无效，只能放行 `unsafe-inline`
    并建议改用 `addEventListener`；检测到第三方脚本来源时明确列出；
    建议先用 `Content-Security-Policy-Report-Only` 观察
  - **hash 漂移检测**（`advise --check`）：改了内联脚本却忘更新 CSP 时退出码 1 拦住，
    可放进 CI
  - 〔来源：commit `69e9471` + README「CSP 顾问」「hash 漂移检测」〕

- **反向导入：接管一个已有响应头配置的项目（`src/importer.mjs`）**
  - 四种格式：`_headers`（Cloudflare Pages/Netlify）、`vercel.json`、nginx `add_header`、
    Caddyfile `header` 块，按文件名与内容特征自动识别，也可 `--format` 指定；
    手写 `.htaccess` 同样支持（`Header set/unset`、`onsuccess`、单引号）
  - 四条刻意的设计决定：① 忠实反映现状，**不顺手补齐**缺失的安全头；
    ② 默认只接管安全响应头；③ 解析不了的行不静默丢弃，都进 `skipped` 并列出来；
    ④ 只恢复得回"名字与取值"，`severity`/`why` 给占位值并标注"尚未人工确认"
  - 退出码 **1** = 现状不满足安全基线（与 `verify` 一致，可作 CI 门禁）
  - 〔来源：commit `2684333` + `8a195d4`（`.htaccess`）+ README「反向导入」四条设计决定〕

- **默认只接管安全响应头（`SECURITY_HEADERS` 显式清单）**
  - 依据是抓了 **9 份公开仓库的真实 `_headers`** 之后改的：真实配置里 `Cache-Control`
    几乎总是按路径分别取值（9 份里 4 份，最多一份有 14 个路径块），而策略模型是
    「一个头一个取值」—— 全量导入会把它们压平成一条，用户一旦
    「导入 → 改名 → generate → 发布」就会用一条规则替换掉对方整套缓存策略，**直接搞坏线上缓存**
  - 过滤下沉到收集器：非安全头的按路径冲突**不再产生警告**（改之前 4 份真实配置各刷一串噪音）
  - 文件里只有非安全头时明确报错，并给出 `--all` 的出路
  - **元测试**：语料中出现的每一个头，要么在 `SECURITY_HEADERS` 里、要么在"刻意排除"
    清单里 —— 不允许有"没考虑过"的漏网
  - 〔来源：commit `cdd7b15` + README「为什么默认不导入 `Cache-Control` 这类头」+
    `fixtures/real-world/SOURCES.md`〕

- **往返一致性守卫：`generate` → `import` 必须回到同一组「名字 → 取值」**
  - nginx / caddy 会把值里的 `"` 转义成 `\"`，导入时必须正确还原 —— 否则"接管别人项目"
    会从第一次生成就开始悄悄改坏配置
  - `scripts/check-roundtrip.mjs` 在内存里跑完整往返、不起子进程，本地与 CI 同一份代码
  - `diffHeaderMaps()` 抽成纯函数便于双向验证（能发现问题 + 不误报相同内容）；
    测试特意用含双引号与反斜杠的取值逼出转义路径
  - 实测：6 种产物 7/7 个头部往返一致
  - 〔来源：commit `2684333` + README「验收标准：往返一致」+ 本地实跑
    `node scripts/check-roundtrip.mjs headers.policy.json`：6/6 全过〕

- **真实语料验证（`fixtures/real-world/`）**
  - 9 份来自公开仓库的真实 `_headers`，`SOURCES.md` 记明来源与获取命令
  - `tests/real-world.test.mjs` 用真实数据跑，**立刻推翻了一个设计时没想到的默认行为**
    （见上一条）
  - 已对站点自己的线上 `_headers` 做完整闭环：`import → 改名 → generate`，
    **产物与线上正在服务的那一份逐字节完全一致**
  - 〔来源：commit `cdd7b15` + README「已对真实站点验证过」+ `fixtures/real-world/SOURCES.md`〕

- **定时线上一致性监控（防回退）（`.github/workflows/conformance.yml`）**
  - 每周一自动校验权威目标（`primary`），不一致时创建/更新 Issue 并打 `header-drift` 标签
  - GitHub Pages 作为对照写入摘要
  - 〔来源：commit `3046b9c` + README「用在你自己的仓库里」第 3 步的说明〕

- **Cloudflare Transform Rules 直接下发（`src/deploy/cloudflare.mjs`）**
  - 设计目标不是"能下发"，而是"**下发失败也能退回来**"：手工粘贴的真正代价不是麻烦，
    而是**静默降级** —— 贴错了线上防护就少了，要等下一轮 `verify` 才发现
  - 四条硬规则：① **默认 dry-run**，`--apply` 才真发（dry-run 打印将要发出的每个请求，
    一个请求都不发）；② **写前必存快照**到 `tmp/cloudflare-deploy/` 后再 PUT，
    `--rollback` 一键还原；③ **只替换 `header-forge:` 前缀的规则**（这个 phase 的
    entrypoint 里可能还有别人建的规则，全量覆盖等于删掉它们且没有任何提示）；
    ④ **令牌只从 `CLOUDFLARE_API_TOKEN` 读**，不支持命令行传参（传参会进 shell 历史与进程列表），
    输出只留前 2 位 + sha256 短哈希，永不落盘
  - `--verify-token` 只读自检，以 API 结果为准
  - 〔来源：commit `055a4ee` + README「下发到 Cloudflare」四条硬规则表 +
    `docs/cloudflare-deploy.md`〕

- **`--paths` 批量校验多个地址**
  - 动机：只校验 `/` 会得出"站点已合规"的错误结论 —— 真实站点经常是根路径一套、
    后台/API/下载路径另一套
  - 三种写法可混用、可重复累加：逗号/换行分隔、`@paths.txt` 文件（空行与 `#` 注释忽略，
    适合把清单签进仓库）、完整 URL 原样使用
  - `--url` 在批量模式下只作为**基准地址**；不给基准时相对路径直接报错（退出码 2），
    而不是猜一个地址
  - **退出码**：`0` 全部一致 · `1` 存在不一致 · `2` 参数或运行错误（含任一地址拉取失败）
  - 拉取失败**不算"不一致"**：拿不到响应时我们并不知道合规不合规，
    报 1 会把"没测到"说成"测出来不合规"
  - 串行执行：报告顺序与输入顺序一致（可复现），也避免把对方站点打出限流
  - 〔来源：commit `f8aae0e` + README「一次校验多个地址（`--paths`）」+ `--help` 的 verify 选项〕

- **SARIF 2.1.0 输出，接入 GitHub Code Scanning（`src/lib/sarif.mjs`）**
  - 挂在 `verify` 上：`--sarif <路径>`；它产出的"缺失/值不符"就是代码扫描要报的问题
  - 设计取舍（每条都直接影响面板好不好用）：只上报 `missing` 与 `mismatch`
    （`extra` 头是"策略未声明"而非违规，站点几乎总有 `Server`/`X-Powered-By`，
    报进去就是永远关不掉的噪音；拉取失败属"没测到"，由退出码 2 表达）；
    `level` 按策略里声明的 severity 映射；`ruleId = header-forge/<状态>/<头名>` **不含 URL**
    （含 URL 的话同一类问题在 10 个路径上就是 10 条规则）；
    `partialFingerprints = sha256(状态|URL|头名)` **不含实际值/期望值/时间戳**
    （站点把 `max-age` 从 600 改成 300 时仍是同一个问题，指纹必须不变，
    否则每跑一次 CI 就新开一条告警）
  - 写完当场自检：JSON 可解析、必填字段与 `level`/`ruleId`/指纹齐全、
    **结果数 = 输入问题数**；自检不过退出码 2
  - 〔来源：commit `f8aae0e` + README「输出 SARIF（接入 GitHub Code Scanning）」取舍表〕

- **工程**
  - **零运行时依赖**：只用 Node 内置模块（`crypto` / `https` / `http` 等），
    CI 里无需 `npm install`，供应链面为零；CI 强制校验
    （`scripts/check-zero-deps.mjs`，当前 35 个源文件）
  - **Node.js >= 20**（`package.json` 的 `engines`）
  - **MIT 许可**（`LICENSE`）
  - **256 项单元测试**，13 个测试文件，全部离线可跑（`node --test tests/`），
    含 Cloudflare 49 项（覆盖 dry-run 不发请求、快照先于 PUT、前缀过滤、脱敏不泄漏令牌）、
    真实语料、往返一致性、`policy.remove` 注入、`--paths`、SARIF
  - CI 多作业：单元测试 + 零依赖校验 / 生成与自证闭环 / 策略质量守卫（坏策略必须被拒）/
    往返一致性与反向导入冒烟
  - 〔来源：`package.json` + `scripts/check-zero-deps.mjs` 实跑（35 个源文件）+
    `tests/` 13 个文件实跑：256 pass / 0 fail + commit `69e9471`/`055a4ee`/`cdd7b15` 的 CI 说明〕

- **文档与元数据**
  - `README.en.md`（英文版，30 秒首屏 + 全文对照）与中文 README 顶部互链
  - `package.json` 补齐 npm 发布元数据：英文 `description`、`keywords`、
    `repository` / `homepage` / `bugs` / `author`，以及 `files` 允许清单
    （排除 `tests/`、`.github/`、dev 脚本）
  - `MIGRATION.md`（从 GitHub Pages 迁出的路径）、`docs/cloudflare-deploy.md`
    （令牌权限、错误码 `9106` / `6111` / `10000` / `403` 的含义、回滚流程）
  - 〔来源：commit `615a1bd` + 仓库文件清单〕

### 修复

> 以下均在本版本**发布之前**的开发期发现并修正，未进入任何已发布版本。
> 按 Keep a Changelog 的惯例保留记录，因为它们各自对应一个真实缺陷。

- **`policy.remove` 的配置注入缺口（安全修复）**：`policy.remove` 的条目从未做过注入校验，
  而 `generators/caddy.mjs` 直接把它渲染成 `-${name}`。于是只要 `headers.policy.json` 可控，
  `generate --only caddy` 就能把任意指令注入 Caddyfile（实测可逃逸出 header 块）。
  修法：策略层新增 `isSafeHeaderName()`（只允许 RFC 7230 token 字符）并校验 `remove` 每项；
  caddy 生成器再加一道断言；htaccess 生成器删掉本地 `TOKEN_RE`、改共用同一判据，避免判据漂移。
  复测：同一注入夹具下 caddy / nginx / htaccess / 全量 四种调用全部退出码 2 且不落盘任何文件；
  真实策略全量 `generate` 仍退出码 0（6 份产物）
  - 〔来源：commit `b3a4135` + `tests/policy-remove-injection.test.mjs` + README「设计决策」表〕

- **同名产物静默覆盖**：`generate --out dist` 会让 **Cloudflare Pages 与 Netlify 两份
  `_headers` 写进同一个路径**，谁后写谁生效 —— 同一份策略，产物取决于生成器遍历顺序。
  内容恰好相同所以没出事，但这是静默的不确定性，也让"生成产物可复现"这条 CI 检查形同虚设。
  修法：落点决策抽成 `planOutputPaths()`，并加断言"五个落点两两不同"
  - 〔来源：commit `cdd7b15` + README「已对真实站点验证过」的括注〕

- **Caddy `- Name`（横线后带空格）被解析成名为「-」的响应头**：真实语料与手写配置里
  两种删除写法都有（`-Name` 与 `- Name`），原来只认前者。现在两种都认，
  并显式排除名字为 `-` 的结果
  - 〔来源：commit `2684333`「顺带修的两个真 bug」第 1 条 + `cdd7b15` 第 5 条〕

- **`skip()` 的参数与字段语义是反的**（`where` 里装说明文字、`line` 里装位置），
  会让 CLI 打出 `[说明文字] 位置` 这种混乱提示。统一为 `skip(where, line)` 并修正两处调用
  - 〔来源：commit `2684333`「顺带修的两个真 bug」第 2 条〕

- **坏策略生成脚本未自建输出目录**，导致 CI 首次运行因目录不存在而失败
  - 〔来源：commit `ed19f70`〕

- **误提交一致性报告产物**：`out-cf/` 与 `out-gh/` 是校验时生成的可再生报告，
  不应进入仓库；`.gitignore` 原先只挡了 `out/`，未覆盖带后缀的同类目录
  - 〔来源：commit `4da69e5`〕

- **README 承诺但未实现的能力**：防回退监控（定时线上一致性校验）此前只有文字承诺，
  本次补齐 `conformance.yml` 与多目标策略
  - 〔来源：commit `3046b9c`〕

- **测试徽章数字与实际不符**：首屏静态徽章未随测试增长同步，属对外声明与实际不符。
  `9868bac` 111 → 204、`e06685c` 204 → 256（只改数字，不动徽章形态）
  - 〔来源：commit `9868bac` + `e06685c`〕

### 安全

- **配置注入防护覆盖每一个渲染字段**：策略值会被渲染进 nginx/caddy 语法，含换行/制表符的
  值一律拒绝；`remove` 的名字同样会进配置语法（caddy 的 `-Name` 是裸渲染），
  所以它必须过与头部名同源的 RFC 7230 token 校验 —— **策略层 + 生成器各一道，缺一不可**
- **拒绝 `unsafe-inline`（script-src）**：策略校验直接拒绝；确需放行必须改用 hash
  或在 `why` 中明确说明。CSP 顾问用 `'sha256-...'` 放行必要的内联脚本
- **Cloudflare 下发的四条硬规则**：默认 dry-run、写前必存快照、只替换 `header-forge:`
  前缀的规则、令牌只从环境变量读且输出脱敏永不落盘
- **`.htaccess` 默认 `always set` + `<IfModule>` 守卫**：错误响应也要有防护；
  缺 `mod_headers` 时没守卫会让整站 500
- **校验响应完整性**：被中断的残缺响应必须判为失败，否则会得出"头部缺失"的错误结论
- **反向导入不替你补齐缺失的头**：补齐意味着站点"看起来合规"而实际没有这些头 ——
  这是最危险的失败方式，有专门的测试断言
- 〔来源：README「设计决策」表 +「反向导入」第 1 条设计决定 +「下发到 Cloudflare」 +
  `.htaccess` 取舍表 + commit `b3a4135`〕

### 已知局限

> 以下直接引自 README「局限」一节，非本 CHANGELOG 自行发明。

- 生成的配置需要**由你部署到对应平台**才会生效；本工具不替你部署
- `verify` 默认校验**单个 URL**；要覆盖按路径分别设置的头，用 `--paths` 把路径列全 ——
  工具不会替你去发现有哪些路径，`paths.txt` 需要你自己维护
- 反向导入**只能恢复"名字与取值"**：`severity`/`why` 是人的判断，配置里没有；
  策略模型一个头只有一个取值，多路径块或多条 `source` 规则会被合并（合并时给出警告）
- Apache `.htaccess` 是**文件级**配置，多两个静默失效点：需要站点已加载 `mod_headers`，
  且允许覆盖（主配置 `AllowOverride FileInfo`），否则整块配置不生效、通常也不报错。
  模拟器能证明"产物里的取值与结构正确"，但**验证不了你的 Apache 是否真的加载了模块、
  是否允许覆盖** —— 部署后请用 `verify` 对线上实测

（README 的「局限」一节共 11 条，另有：nginx `location` 嵌套 / Caddy 匹配器无法在策略模型
中表达、`.htaccess` 没有路径模式、`Header always unset Server` 在部分配置下不生效、
CSP 顾问基于静态 HTML 分析、不处理 DNS 层面的问题、`--paths` 是串行的、
SARIF 告警位置固定指向策略文件、SARIF 只上报 `missing` 与 `mismatch`。）

[Unreleased]: https://github.com/Frank2673/header-forge/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Frank2673/header-forge/releases/tag/v0.1.0
