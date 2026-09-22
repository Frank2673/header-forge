// 生成三种"坏策略"用于负向验证（放在仓库外，不污染仓库）
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';

const base = JSON.parse(readFileSync('headers.policy.json', 'utf8'));
const outDir = process.argv[2] || 'tmp/bad-policies';

/* 目录可能不存在（CI 上就是如此）—— 必须自己建，否则首次运行直接崩 */
mkdirSync(outDir, { recursive: true });

/* 1. script-src 放行 unsafe-inline */
const weak = structuredClone(base);
weak.headers['Content-Security-Policy'].value = weak.headers['Content-Security-Policy'].value.replace(
  "script-src 'self'",
  "script-src 'self' 'unsafe-inline'"
);
writeFileSync(`${outDir}/weak.policy.json`, JSON.stringify(weak, null, 2));

/* 2. 配置注入：值里带换行 */
const inject = structuredClone(base);
inject.headers['X-Content-Type-Options'].value = 'nosniff\nadd_header X-Evil "1"';
writeFileSync(`${outDir}/inject.policy.json`, JSON.stringify(inject, null, 2));

/* 3. 缺少 CSP（破坏安全基线） */
const noCsp = structuredClone(base);
delete noCsp.headers['Content-Security-Policy'];
writeFileSync(`${outDir}/nocsp.policy.json`, JSON.stringify(noCsp, null, 2));

/* 4. HSTS max-age 过短 */
const weakHsts = structuredClone(base);
weakHsts.headers['Strict-Transport-Security'].value = 'max-age=600; includeSubDomains';
writeFileSync(`${outDir}/weakhsts.policy.json`, JSON.stringify(weakHsts, null, 2));

console.log('已生成 4 份坏策略到', outDir);
