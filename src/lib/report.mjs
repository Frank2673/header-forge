/**
 * 一致性校验报告
 *
 * 输出三种形态：Markdown（给人看）、JSON（给机器看）、控制台摘要（给 CI 看）。
 *
 * @module lib/report
 */

const TOOL = 'header-forge';

/**
 * Markdown 报告
 * @param {object} input {policy, results, url, meta}
 */
export function renderMarkdown({ policy, results, url, meta }) {
  const { passed, failed, missing, extra } = summarizeResults(results);
  const lines = [];

  lines.push('# 安全响应头一致性报告');
  lines.push('');
  lines.push(`> 由 \`${TOOL} v${meta.version}\` 于 ${meta.startedAt} 生成`);
  lines.push('');
  lines.push(`- 校验地址：${url}`);
  if (meta.finalUrl && meta.finalUrl !== url) lines.push(`- 最终地址：${meta.finalUrl}`);
  if (meta.status) lines.push(`- HTTP 状态：${meta.status}`);
  lines.push(`- 策略文件：\`${meta.policyPath}\``);
  lines.push('');

  lines.push('## 概览');
  lines.push('');
  lines.push('| 指标 | 数值 |');
  lines.push('| :--- | :--- |');
  lines.push(`| 策略中要求的头 | ${Object.keys(policy.headers).length} |`);
  lines.push(`| ✅ 符合 | ${passed.length} |`);
  lines.push(`| ❌ 缺失 | ${missing.length} |`);
  lines.push(`| ⚠️ 值不符 | ${failed.length} |`);
  lines.push(`| ℹ️ 策略外但仍存在的头 | ${extra.length} |`);
  lines.push('');

  const compliant = missing.length === 0 && failed.length === 0;
  lines.push(compliant ? '**结论：✅ 完全符合策略**' : '**结论：❌ 与策略存在差异（见下方明细）**');
  lines.push('');

  if (missing.length) {
    lines.push('## ❌ 缺失的响应头');
    lines.push('');
    for (const item of missing) {
      lines.push(`### ${item.name}`);
      lines.push('');
      lines.push(`- 严重度：**${item.severity}**`);
      lines.push(`- 策略要求值：\`${item.expected}\``);
      if (item.why) lines.push(`- 为什么重要：${item.why}`);
      lines.push('');
    }
  }

  if (failed.length) {
    lines.push('## ⚠️ 值与策略不符');
    lines.push('');
    for (const item of failed) {
      lines.push(`### ${item.name}`);
      lines.push('');
      lines.push(`- 严重度：**${item.severity}**`);
      lines.push(`- 线上实际值：\`${item.actual}\``);
      lines.push(`- 策略要求值：\`${item.expected}\``);
      lines.push(`- 差异：${item.note}`);
      lines.push('');
    }
  }

  if (passed.length) {
    lines.push('## ✅ 符合策略的头');
    lines.push('');
    for (const item of passed) lines.push(`- \`${item.name}\`: \`${item.actual}\``);
    lines.push('');
  }

  if (extra.length) {
    lines.push('## ℹ️ 策略外但线上存在的头');
    lines.push('');
    lines.push('这些头不在策略中，可能是平台自带或遗留配置，建议人工确认：');
    lines.push('');
    for (const item of extra) lines.push(`- \`${item.name}\`: \`${item.value}\``);
    lines.push('');
  }

  lines.push('---');
  lines.push('');
  lines.push(`<sub>${TOOL} v${meta.version} · 零依赖 · 校验逻辑与生成逻辑共用同一份策略</sub>`);

  return lines.join('\n');
}

/**
 * JSON 报告
 */
export function renderJson({ policy, results, url, meta }) {
  const summary = summarizeResults(results);
  return {
    tool: TOOL,
    version: meta.version,
    startedAt: meta.startedAt,
    url,
    finalUrl: meta.finalUrl || null,
    status: meta.status ?? null,
    policyPath: meta.policyPath,
    policyHeaders: Object.keys(policy.headers),
    compliant: summary.missing.length === 0 && summary.failed.length === 0,
    summary: {
      required: Object.keys(policy.headers).length,
      passed: summary.passed.length,
      missing: summary.missing.length,
      mismatched: summary.failed.length,
      extra: summary.extra.length,
    },
    details: results,
  };
}

/** 控制台摘要 */
export function renderSummary({ results }) {
  const { passed, failed, missing } = summarizeResults(results);
  const ok = missing.length === 0 && failed.length === 0;

  const lines = [];
  lines.push(
    `${ok ? '✅ 完全符合策略' : '❌ 与策略不一致'} | 符合 ${passed.length} | 缺失 ${missing.length} | 值不符 ${failed.length}`
  );
  for (const item of missing) lines.push(`  - [缺失] ${item.name}（应设为 ${item.expected}）`);
  for (const item of failed) lines.push(`  - [不符] ${item.name}：实际 ${item.actual} / 期望 ${item.expected}`);

  return lines.join('\n');
}

/**
 * 归类校验结果
 */
export function summarizeResults(results) {
  return {
    passed: results.filter((r) => r.status === 'pass'),
    failed: results.filter((r) => r.status === 'mismatch'),
    missing: results.filter((r) => r.status === 'missing'),
    extra: results.filter((r) => r.status === 'extra'),
  };
}
