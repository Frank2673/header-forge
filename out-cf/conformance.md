# 安全响应头一致性报告

> 由 `header-forge v0.1.0` 于 2026-09-23T16:41:24.962Z 生成

- 校验地址：https://frank2673-site.pages.dev/
- HTTP 状态：200
- 策略文件：`headers.policy.json`

## 概览

| 指标 | 数值 |
| :--- | :--- |
| 策略中要求的头 | 7 |
| ✅ 符合 | 7 |
| ❌ 缺失 | 0 |
| ⚠️ 值不符 | 0 |
| ℹ️ 策略外但仍存在的头 | 1 |

**结论：✅ 完全符合策略**

## ✅ 符合策略的头

- `Strict-Transport-Security`: `max-age=31536000; includeSubDomains`
- `Content-Security-Policy`: `default-src 'self'; script-src 'self' 'sha256-ab1dsL2WBfLFbNhNPNbdT9zQ5o8/OlH88pYN4AqLL9k='; style-src 'self'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests`
- `X-Content-Type-Options`: `nosniff`
- `Referrer-Policy`: `strict-origin-when-cross-origin`
- `Permissions-Policy`: `geolocation=(), camera=(), microphone=(), payment=(), usb=(), magnetometer=(), gyroscope=()`
- `X-Frame-Options`: `DENY`
- `Cross-Origin-Opener-Policy`: `same-origin`

## ℹ️ 策略外但线上存在的头

这些头不在策略中，可能是平台自带或遗留配置，建议人工确认：

- `Server`: `cloudflare`

---

<sub>header-forge v0.1.0 · 零依赖 · 校验逻辑与生成逻辑共用同一份策略</sub>