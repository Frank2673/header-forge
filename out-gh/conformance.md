# 安全响应头一致性报告

> 由 `header-forge v0.1.0` 于 2026-09-23T16:41:28.056Z 生成

- 校验地址：https://frank2673.github.io/
- HTTP 状态：200
- 策略文件：`headers.policy.json`

## 概览

| 指标 | 数值 |
| :--- | :--- |
| 策略中要求的头 | 7 |
| ✅ 符合 | 0 |
| ❌ 缺失 | 6 |
| ⚠️ 值不符 | 1 |
| ℹ️ 策略外但仍存在的头 | 1 |

**结论：❌ 与策略存在差异（见下方明细）**

## ❌ 缺失的响应头

### Content-Security-Policy

- 严重度：**medium**
- 策略要求值：`default-src 'self'; script-src 'self' 'sha256-ab1dsL2WBfLFbNhNPNbdT9zQ5o8/OlH88pYN4AqLL9k='; style-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests`
- 为什么重要：限制脚本与资源的加载来源，作为 XSS 的第二道防线。内联的防闪烁主题脚本用 sha256 hash 放行（而非 unsafe-inline），因此修改该脚本后必须重新生成 hash —— 用 `node src/index.mjs advise --html <index.html> --check headers.policy.json` 可检测漂移。

### X-Content-Type-Options

- 严重度：**low**
- 策略要求值：`nosniff`
- 为什么重要：禁止浏览器按内容猜测 MIME 类型，避免把上传/静态文件当作脚本执行。

### Referrer-Policy

- 严重度：**low**
- 策略要求值：`strict-origin-when-cross-origin`
- 为什么重要：跨站跳转时只发送来源域而不带完整路径，避免 URL 中的信息被第三方日志记录。

### Permissions-Policy

- 严重度：**info**
- 策略要求值：`geolocation=(), camera=(), microphone=(), payment=(), usb=(), magnetometer=(), gyroscope=()`
- 为什么重要：本站不需要任何浏览器硬件能力，显式关闭可缩小被注入脚本后的可利用面。

### X-Frame-Options

- 严重度：**medium**
- 策略要求值：`DENY`
- 为什么重要：禁止页面被 iframe 嵌套，防止点击劫持。与 CSP 的 frame-ancestors 形成双保险（覆盖老浏览器）。

### Cross-Origin-Opener-Policy

- 严重度：**low**
- 策略要求值：`same-origin`
- 为什么重要：把本站的浏览器上下文与外部窗口隔离，缓解 Spectre 类侧信道与窗口引用滥用。

## ⚠️ 值与策略不符

### Strict-Transport-Security

- 严重度：**medium**
- 线上实际值：`max-age=31556952`
- 策略要求值：`max-age=31536000; includeSubDomains`
- 差异：线上值缺少 includeSubDomains

## ℹ️ 策略外但线上存在的头

这些头不在策略中，可能是平台自带或遗留配置，建议人工确认：

- `Server`: `GitHub.com`

---

<sub>header-forge v0.1.0 · 零依赖 · 校验逻辑与生成逻辑共用同一份策略</sub>