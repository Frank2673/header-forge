# 迁移指南：让响应头真正生效

## 先说清楚问题

**GitHub Pages 不支持自定义 HTTP 响应头。** 这不是配置问题，是平台限制：它只负责把文件发出去，不提供修改响应的入口。

所以 `frank2673.github.io` 上的这 6 项缺失，**在 GitHub Pages 上无论怎么改都无法修复**：

```
Content-Security-Policy · X-Frame-Options · X-Content-Type-Options
Referrer-Policy · Permissions-Policy · Cross-Origin-Opener-Policy
（外加 HSTS 缺少 includeSubDomains）
```

结论很直接：**要让响应头生效，必须让流量经过一个能改响应头的层。** 下面三个方案按成本排序。

---

## 方案 A：Cloudflare Pages（推荐 · 免费 · 不需要域名）

免费套餐原生支持 `_headers` 文件，用它托管同一个静态站点即可，无需购买域名，会得到一个 `*.pages.dev` 地址。

### 步骤

1. 在仓库根目录加入生成的 `_headers`：
   ```bash
   node src/index.mjs generate --policy headers.policy.json --out . --only cloudflare-pages
   ```
2. 打开 Cloudflare Dashboard → **Workers & Pages** → **Create** → **Pages** → **Connect to Git**
3. 授权并选择你的静态站仓库
4. 构建设置（纯静态站）：
   - Framework preset: **None**
   - Build command: **留空**
   - Build output directory: **`/`**（或你的站点目录）
5. 点 **Save and Deploy**，等待部署完成
6. Cloudflare 会分配一个 `https://<项目名>.pages.dev` 地址

### 验证

```bash
node src/index.mjs verify --policy headers.policy.json --url https://<项目名>.pages.dev/
```

期望输出：`✅ 完全符合策略`。

### 代价与权衡

- ✅ 免费、无需域名、无需信用卡
- ⚠️ 站点地址变成 `*.pages.dev`（除非后续绑定自有域名）
- ⚠️ 两个站点并存时要注意内容同步（同一次 push 可以同时部署到两边）

### 回滚

删除 Cloudflare Pages 项目即可，GitHub Pages 上的原站点不受影响 —— 本方案是**纯增量**，不动现有部署。

---

## 方案 B：Netlify（免费 · 同样不需要域名）

与方案 A 几乎等价，同样用 `_headers`：

1. 生成配置：
   ```bash
   node src/index.mjs generate --policy headers.policy.json --out . --only netlify
   ```
2. Netlify → **Add new site** → **Import an existing project** → 选择仓库
3. Build command 留空，Publish directory 填站点目录
4. 部署完成后得到 `https://<站点名>.netlify.app`

**注意**：Netlify 的路径匹配比 Cloudflare 严格 —— `/*` 不一定会覆盖带扩展名的静态资源。若发现某些资源没带上响应头，在 `_headers` 里显式补上对应路径。

---

## 方案 C：自有域名 + Cloudflare 代理（彻底方案，需域名）

如果你希望**品牌域名 + 完整响应头**，这是唯一路径。响应头由 Cloudflare 的 Transform Rules 在回源后改写。

### 步骤

1. 注册一个域名（年费通常 10 美元上下）
2. 在 Cloudflare 添加该域名，把域名的 NS 交给 Cloudflare
3. DNS 里加一条 CNAME 指向 `frank2673.github.io`，**开启代理（橙色云朵）**
4. 在 GitHub 仓库 Settings → Pages → Custom domain 填入你的域名
5. Cloudflare → **Rules** → **Transform Rules** → **Modify Response Header**，按生成的策略逐条添加
   （也可以用 `dist/` 里的 `_headers` 内容作为对照表手工录入）
6. SSL/TLS 模式设为 **Full**（不要用 Flexible，否则会重定向循环）

### 验证

```bash
node src/index.mjs verify --policy headers.policy.json --url https://你的域名/
```

### 代价与权衡

- ✅ 保留品牌域名，响应头完整生效，还能顺带开 WAF / 缓存 / 分析
- ⚠️ 需要域名成本，且 SSL 模式配错会出现重定向循环（这是最常见的坑）

---

## 三个方案怎么选

| 你的目标 | 选择 |
|---|---|
| 先验证效果、不想花钱 | **方案 A**（Cloudflare Pages） |
| 已经在用 Netlify | 方案 B |
| 要品牌域名 + 完整控制 | 方案 C |

无论选哪个，`headers.policy.json` 都是同一份 —— 这正是"配置即代码"的价值：**换平台不用重写需求**。

---

## 迁移后建议保留两道防线

1. **CI 校验线上一致性**（防回退）
   ```yaml
   - run: node src/index.mjs verify --policy headers.policy.json
   ```
   任何人改掉部署配置导致防护降级，CI 当天就红。

2. **CSP hash 漂移检查**（防"改了脚本忘了改策略"）
   ```yaml
   - run: node src/index.mjs advise --html index.html --check headers.policy.json
   ```

---

## 关于 DMARC

surface-watch 还报了一条「缺少 DMARC 记录」。这条**无法通过响应头解决**，它属于 DNS：

- `frank2673.github.io` 是 `github.io` 的子域，**你无权为它添加 DNS 记录**
- 只有在方案 C（自有域名）落地后，才能在你的域名上添加 `_dmarc` TXT 记录

也就是说：**方案 C 是同时解决响应头与邮件伪造面的唯一路径。** 如果将来要拿这个站点当正式门面，值得考虑。
