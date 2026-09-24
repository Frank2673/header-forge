#!/usr/bin/env node
/**
 * 往返一致性检查：generate → import 必须得到同一组「名字 → 取值」
 *
 * 这是反向导入的验收标准。任何转义/格式细节上的不对称都会在这里暴露 ——
 * 例如 nginx 把值里的 `"` 转义成 `\"`，导入时必须能正确还原，
 * 否则"接管别人的项目"会从第一次生成开始就悄悄改坏配置。
 *
 * 本脚本在内存里跑完整往返，不依赖 dist/ 是否已生成，也不起子进程 ——
 * 所以它本地能跑、CI 也能跑，同一份代码同一个结论。
 *
 * 用法：node scripts/check-roundtrip.mjs [策略文件]
 */

import { resolve } from 'node:path';
import { loadPolicy } from '../src/lib/policy.mjs';
import { generateAll } from '../src/generators/index.mjs';
import { importConfig } from '../src/importer.mjs';

/** 生成器 id → 对应的导入格式 */
const FORMAT_BY_GENERATOR = {
  'cloudflare-pages': 'headers',
  netlify: 'headers',
  vercel: 'vercel',
  nginx: 'nginx',
  caddy: 'caddy',
};

/**
 * 比较两组「名字 → 取值」，给出差异
 *
 * 抽成纯函数是为了能被负向测试：一个"永远通过"的往返守卫毫无价值，
 * 必须能证明它在真的出现不对称时会失败。
 *
 * @param {Record<string,string>} expected
 * @param {Record<string,string>} got
 * @returns {{missing: string[], extra: string[], different: Array<{name:string,expected:string,got:string}>}}
 */
export function diffHeaderMaps(expected, got) {
  const missing = Object.keys(expected).filter((n) => !(n in got));
  const extra = Object.keys(got).filter((n) => !(n in expected));
  const different = Object.keys(expected)
    .filter((n) => n in got && got[n] !== expected[n])
    .map((n) => ({ name: n, expected: expected[n], got: got[n] }));

  return { missing, extra, different };
}

/**
 * 跑一次往返，返回逐项结果
 * @param {object} policy
 * @returns {{results: Array, failures: number, expectedCount: number}}
 */
export function checkRoundTrip(policy) {
  const expected = {};
  for (const header of Object.values(policy.headers)) expected[header.name] = header.value;

  const results = [];
  let failures = 0;

  for (const artifact of generateAll(policy)) {
    const format = FORMAT_BY_GENERATOR[artifact.id];
    /* 往返测的是"生成器与解析器是否严格对称"，因此导入全部头；
       默认的 security 过滤是产品层面的取舍，不该掺进这条不变式。 */
    const imported = importConfig(artifact.content, { format, filename: artifact.filename, include: 'all' });

    const entry = { id: artifact.id, format, ok: false };
    results.push(entry);

    if (!imported.ok) {
      entry.reason = `导入失败：${imported.error}`;
      failures += 1;
      continue;
    }

    /* allowStronger 是给 verify 用的语义，往返必须逐字节相等 */
    const { missing, extra, different } = diffHeaderMaps(expected, imported.headers);

    if (missing.length || extra.length || different.length) {
      entry.reason = [
        missing.length ? `缺少 ${missing.join(', ')}` : '',
        extra.length ? `多出 ${extra.join(', ')}` : '',
        different.length ? `取值不同 ${different.map((d) => d.name).join(', ')}` : '',
      ]
        .filter(Boolean)
        .join('；');
      entry.details = different;
      failures += 1;
      continue;
    }

    entry.ok = true;
    entry.count = Object.keys(expected).length;
  }

  return { results, failures, expectedCount: Object.keys(expected).length };
}

/* ------------------------------- CLI ------------------------------- */

if (process.argv[1] && /check-roundtrip\.mjs$/.test(process.argv[1])) {
  const policyPath = resolve(process.argv[2] || 'headers.policy.json');

  let policy;
  try {
    policy = loadPolicy(policyPath);
  } catch (err) {
    console.error(`🛑 无法载入策略：${err.message}`);
    process.exit(2);
  }

  const { results, failures, expectedCount } = checkRoundTrip(policy);

  console.log(`🔄 往返一致性检查（策略：${policyPath}）`);
  console.log(`   原始策略有 ${expectedCount} 个响应头\n`);

  for (const r of results) {
    console.log(
      `${r.ok ? '✅' : '❌'} ${r.id.padEnd(18)} ${r.format.padEnd(8)} ${r.ok ? `${r.count}/${expectedCount} 个头部往返一致` : r.reason}`
    );
    for (const d of r.details || []) {
      console.log(`      ${d.name}`);
      console.log(`        原：${d.expected}`);
      console.log(`        回：${d.got}`);
    }
  }

  console.log('');
  if (failures === 0) {
    console.log('✅ 五种产物的往返一致性全部通过');
    process.exit(0);
  }
  console.error(`❌ ${failures} 种产物往返不一致 —— generate 与 import 之间存在不对称`);
  process.exit(1);
}
