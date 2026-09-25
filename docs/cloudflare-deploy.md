# Cloudflare Transform Rules 下发（dry-run · 回滚 · 令牌自检）

> 对应 README 路线图那条「支持 Cloudflare Transform Rules API 直接下发（省去手工粘贴）」。
> 工具：`src/deploy/cloudflare.mjs`（零依赖，Node ≥ 20）。
> 本页所有**本机可验**的结论都附了实际命令与输出；凡是没验过的，一律在文末「未验项」里点名，不混进结论。

---

## 1. 为什么不能靠手工在控制台粘贴

这个 phase（`http_response_headers_transform`）的 entrypoint 是**整段配置**，
PUT 是全量覆盖语义。手工做这件事有三个真实的坑：

| 坑 | 后果 |
|---|---|
| 粘错一个字符 | 防护静默降级，要等下一轮线上校验才发现 |
| 没注意这个 phase 里还有别人建的规则 | 一把覆盖 = 删掉它们，且不会有任何提示 |
| 改坏了 | 没有退路 |

所以工具的三条硬规则：**默认 dry-run**、**写之前先存快照**、**令牌只从环境变量读且永不落盘**。
另外 `apply` 走的是**范围合并**：只替换描述带 `header-forge:` 前缀的规则，
别人的规则逐字保留（这条由测试断言守着，见 `tests/cloudflare.test.mjs`）。

---

## 2. 三步走

```powershell
# ① 自检令牌（只读，不改任何东西）
$env:CLOUDFLARE_API_TOKEN = "<从控制台 Copy 按钮复制的令牌值>"
node src/deploy/cloudflare.mjs --verify-token

# ② 预演（默认行为，一个请求都不发）
node src/deploy/cloudflare.mjs --zone <zone-id 或域名>

# ③ 真下发（会先 GET 现状存快照，再 PUT 覆盖）
node src/deploy/cloudflare.mjs --zone <zone-id 或域名> --apply
```

常用参数：

| 参数 | 作用 |
|---|---|
| `--zone <id\|域名>` | 32 位 hex 视为 zone id；否则先走 `GET /zones?name=` 解析 |
| `--out <目录>` | 快照目录（默认 `tmp/cloudflare-deploy`） |
| `--expression <表达式>` | 规则生效条件，默认 `true`（整个 zone）；要按路径收窄就传 `starts_with(http.request.uri.path, "/app")` |
| `--from-snapshot <文件>` | dry-run 时用快照预演合并结果，让预览与 apply 一字不差 |
| `--base-url <URL>` | API 基址，默认 `https://api.cloudflare.com/client/v4`；**离线自证必须覆盖它** |
| `--rollback <快照>` | 还原；不加 `--apply` 只预览 |

退出码：**0** 成功 / **1** Cloudflare 明确拒绝（认证、权限、参数错误码）/ **2** 无法完成（缺令牌、文件不存在、参数非法、连接失败、响应非 JSON）。

---

## 3. 令牌自检清单

按顺序走一遍，**第 1–9 项不发任何请求**（工具在本地就判完，省掉一轮 CI 的时间）。

### 3.1 本地形状体检（不发请求）

命令：

```powershell
node src/deploy/cloudflare.mjs --verify-token
```

输出里的「令牌 / 构成指纹」两行就是体检结果（样例取自**本机假服务**，不是真实账号）：

```
  令牌：cf*** (sha256:b303814744da) · 长度 45 · 格式 scannable
  构成指纹：大写 10｜小写 14｜数字 20｜连字符 0｜下划线 1｜其它 0
```

| # | 检查项 | 判据 |
|---|---|---|
| 1 | 值从哪来 | **必须**用控制台的 Copy 按钮复制。选中页面文本复制会带进不可见字符 —— 本项目历史上就是这么翻车的 |
| 2 | 有没有非 ASCII / 控制字符 | 有 → 直接阻断，并列出十六进制码点（如 `U+200B` 零宽空格、`U+FEFF` BOM） |
| 3 | 有没有空格 | 有 → 阻断（HTTP 头里的 Bearer 值不能含空格） |
| 4 | 是不是以 `http://` / `https://` 开头 | 是 → 阻断：「像是把 API 网址复制进来了」 |
| 5 | 有没有 `://` | 有 → 阻断：「像是一段网址」 |
| 6 | 是不是以 `curl` / `wget` / `export` / `set` / `Invoke-` / `node` / `python` / `npm` 开头 | 是 → 阻断：「粘进来的是命令文本」 |
| 7 | 值里有没有自带 `Bearer ` 前缀 | 有 → 阻断（工具会自己加，重复会导致 6111） |
| 8 | 是不是别的平台的凭据 | `ghp_` / `github_pat_` / `glpat-` / `AKIA` / `xoxb-` / `AIza` / `sk-` 开头 → 阻断并指名道姓 |
| 9 | 前缀与长度 | `cfut_`（用户级）/ `cfat_`（账户级）/ `cfk_`（Global API Key）或 40 位旧格式。**认不出来只告警不阻断** —— 格式假设会过时，把最终判定权交给 API |
| 10 | 环境变量是否真的赋成了值 | PowerShell 里 `'$env:CLOUDFLARE_API_TOKEN'` 用单引号只是字面量；`--apply` 缺令牌会安全失败并提示 |
| 11 | `--verify-token` 的 API 结果 | `success=true` + `status=active` 才叫有效 |
| 12 | 权限是否够 | 见第 4 节 —— **自检通过 ≠ 有下发权限**，这是最容易误判的一步 |

### 3.2 「值根本不是令牌」怎么一眼看出来

工具的判据是**字符构成指纹 + 形态标记**，而不是「长度对不对」：

```
总长 62｜大写 0｜小写 48｜数字 1｜连字符 0｜下划线 0｜其它 13   → 13 个「其它」字符
前缀为「cu」，不是 cf 开头
非字母数字字符的集合：[ : / . ]
```

上面是本项目历史上真实抓到的形态（记录在 `tmp/commit-msg7.txt`）：**存进去的不是令牌，而像一段网址或命令文本**。
工具把这类判断固化成阻断项，并在输出里只暴露「前 2 位 + *** + sha256 短哈希」——
足以让你认出「我粘错对象了」，又不构成泄露。

> 脱敏口径与 surface-watch 一致：只留前 2 位。留 4 位以上时，
> 配合长度与构成指纹就足以在小搜索空间里做候选枚举。

---

## 4. 令牌权限范围

| 用途 | 需要的权限 | 说明 |
|---|---|---|
| 按域名解析 zone（`GET /zones?name=`） | **Zone → Zone → Read** | 权限不足时这个接口**返回空列表而不是 403** —— 最容易误判的一种失败，工具会提示这一点 |
| 读写 entrypoint ruleset（GET / PUT） | **Zone → Transform Rules → Edit** | 本工具真正要用的权限 |
| `GET /user/tokens/verify` | 无业务权限要求 | 任何有效令牌都能调；**因此它通过不代表能下发** |
| `GET /accounts/<id>`（本工具不用） | Account Settings: Read | 项目历史实测：最小权限令牌在这里返回 403 属正常，不应误判为故障（来源：`tmp/commit-msg9.txt`） |

要点：

- **Zone Resources 必须包含目标 zone**（选 All zones 或明确勾选）。
- 权限组名称以控制台当前措辞为准；本项目**未在真实账号上核对过权限组名**。
- 推荐做法：单独建一个只给「Zone Read + Transform Rules Edit」、只覆盖目标 zone 的令牌，别用 Global API Key。

---

## 5. 错误码对照

工具会把 code 翻译成「你现在该去改什么」。下表标了每一行的来源，**别把没验过的当验过的**：

| HTTP | code | 含义 | 处置 | 来源 |
|---|---|---|---|---|
| 401 | `10000` | Authentication error：令牌无效 / 已吊销 / 压根没送到 | 先 `--verify-token`；再按第 3 节清单逐项核对 | 本机假服务注入验证过**处理逻辑**；真实账号未验证 |
| 403 | `9109` | Unauthorized to access requested resource：令牌有效但权限/资源范围不含目标 | 补 Zone Read + Transform Rules Edit，确认 Zone Resources | 本机假服务注入验证过**处理逻辑**；真实账号未验证 |
| 403 | — | 通用权限不足（形态不唯一） | 同上 | 文档知识 |
| 400 | `6003` + `6111` | Invalid request headers / **Invalid format for Authorization header** | 值里有脏字符，或值根本不是令牌 | **项目历史实测**：`tmp/commit-msg4.txt` 逐字记录了 CI 收到的原始响应 |
| 400 | `9106` | 认证头缺失 / 旧式鉴权路径 | 只用 `Authorization: Bearer <token>`，不要混 `X-Auth-Email`/`X-Auth-Key`；查代理是否吃掉 Authorization | **项目历史实测中出现过该 code**（`tmp/commit-msg3.txt` 只记了 `status 400 / code 9106`，未记 message）；官方措辞未核对 |
| 400 | — | 请求体被拒（rules 结构不对） | 对照工具打印的原始响应体检查 `action` / `expression` / `action_parameters` | 本机假服务注入验证过处理逻辑 |
| 404 | `7003` | 路由 / 对象标识不存在：zone id 错，或**该 phase 还没有 entrypoint ruleset** | 核对 zone id；先在控制台建一条任意规则再跑工具 | 本机假服务注入 + 文档知识 |
| 429 | — | 限流 | 等一会儿再试 | 文档知识 |
| 5xx | — | Cloudflare 侧故障 | **先 GET 看线上是否已经改了**，再决定重试或回滚 | 文档知识 |

---

## 6. 回滚设计

### 6.1 快照是什么

`--apply` 在**任何写操作之前**先 `GET` 现有 entrypoint，把 API 原样返回的 `result` 存成：

```
<--out 目录>/cf-ruleset-before-<UTC 时间戳>.json
```

时间戳进文件名，**不覆盖旧快照**。文件里是 API 的原始结果对象，回滚就是把它原样 PUT 回去 ——
工具不对它做任何「理解」，这是「还原一致」能被断言的前提。

### 6.2 回滚三步

```powershell
# ① 预览（不发请求）：确认要还原成几条、都是什么
node src/deploy/cloudflare.mjs --rollback tmp/cloudflare-deploy/cf-ruleset-before-<ts>.json --zone <zone-id>

# ② 真还原
node src/deploy/cloudflare.mjs --rollback tmp/cloudflare-deploy/cf-ruleset-before-<ts>.json --zone <zone-id> --apply

# ③ 确认线上响应头回到预期
node src/index.mjs verify --policy headers.policy.json
```

### 6.3 风险提示（这几条必须读）

1. **回滚是「整体还原」，不是「撤销本次改动」**：快照之后别人做的任何改动也会被一并抹掉。
2. **回滚失败时线上可能处于中间态**：所以处置顺序永远是「先 GET 看现状 → 再决定重试还是再回滚」，不是无脑重试。
3. **连接断开 ≠ 没改成**：网络错误发生在 PUT 之后时，线上可能已经改了。工具在断连时会明确提示这一点，并保留快照与回滚命令。
4. **控制台手工改名/删除本工具的规则后，回滚仍会整体还原** —— 工具只认 `header-forge:` 前缀。
5. **跨 zone 拒绝**：`--zone` 与快照里的 zone id 不一致时直接拒绝，不允许把 A 区的配置还原到 B 区。
6. 快照里**不会有令牌**（工具保存的是 API 的 result，并在写盘后自检一遍；一旦检出明文会中止，不发 PUT）。

---

## 7. 离线自证（不打真实 API）

工具默认基址就是真实 API，**离线验证必须显式覆盖 `--base-url`**。
仓库里带了一个只监听 `127.0.0.1` 的假服务：`tmp/cloudflare-dryrun/fake-cf.mjs`
（覆盖 `/user/tokens/verify`、`/zones`、entrypoint 的 GET/PUT，记录请求 JSONL，支持注入 401 / 403 / 9106 / 6111 / 断连）。

```powershell
# 起假服务（端口 0 = 随机；这里用固定端口便于对账）
node tmp/cloudflare-dryrun/fake-cf.mjs --port 8791 --log tmp/cloudflare-dryrun/evidence/requests.jsonl

# 另开一个终端：dry-run（假服务侧请求应为 0）
node src/deploy/cloudflare.mjs --zone example-zone.test --base-url http://127.0.0.1:8791/client/v4

# apply → 快照 → rollback，最后逐条对账
node src/deploy/cloudflare.mjs --zone example-zone.test --apply --base-url http://127.0.0.1:8791/client/v4 --out tmp/cloudflare-dryrun/evidence/out
node tmp/cloudflare-dryrun/check-evidence.mjs tmp/cloudflare-dryrun/evidence --policy headers.policy.json
```

`check-evidence.mjs` 会用断言核对四件事：apply 的 PUT body 逐字等于「别人的规则 + 策略渲染的规则」、
快照内容等于 apply 前的现状、rollback 后服务端状态与快照逐字一致、整个取证目录里没有令牌明文。

单元/集成测试：`tests/cloudflare.test.mjs`（自带进程内假服务，不依赖 `tmp/`）。

```powershell
# 本机沙箱禁子进程命名管道，npm test 会 spawn EPERM —— 用这个口径
node --test --test-isolation=none tests/cloudflare.test.mjs
```

---

## 8. 未验项（不要当已验证）

1. **从未对 `api.cloudflare.com` 发起任何请求**：本页所有「已验证」都指在本机假服务上的行为。
2. **真实账号上的行为未验证**，包括：权限组的确切名称与勾选方式、9106 的官方 message 措辞、
   该 zone 尚未建过 ruleset 时的真实响应形态、以及限流阈值。
3. **单条规则里同时下发多个 header（`operation: set` 与 `remove` 混合）在真实 API 上是否被接受**：
   依据的是 Cloudflare 的 `action_parameters.headers` 是映射这一点，**未在真实账号验证**。
   真要上生产，建议先用一个无关紧要的 zone / 或先只 set 一个头试一次。
4. **`PUT` 是否需要带规则 `id` 才能保住规则身份**：本工具保留别人的规则时是原样带 `id` 回写的，
   真实 API 对「不带 id 的新规则」的行为（新建 vs 报错）未验证。
5. 工具**不会创建** ruleset：该 phase 还没有 entrypoint 时直接报错并让你先去控制台建一条 —— 这是刻意的保守选择。
