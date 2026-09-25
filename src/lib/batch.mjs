/**
 * 批量一致性校验
 *
 * 解决的问题：真实站点几乎不会只有"/"一个地址带安全头。常见形态是
 * 根路径一套、后台/API/下载路径另一套（甚至有的平台按路径分别配 header）。
 * 只校验一个 URL 会得出"站点已合规"的错误结论 —— 那正是本项目最想消灭的
 * 失败方式（看起来通过了，实际没生效）。
 *
 * 三层职责划分：
 *   1. `--paths` 的解析（列表 / @文件 / 相对路径拼接）—— 纯函数，可单测
 *   2. 逐条校验后的归类与汇总 —— 纯函数，退出码语义在这里定死
 *   3. 报告渲染 —— 与单 URL 形态分开，避免改坏既有 `conformance.json` 的消费者
 *
 * 退出码语义（与单 URL 形态一致，只是从"一个地址"推广到"一批地址"）：
 *   0 = 全部一致
 *   1 = 存在不一致（且没有运行错误）
 *   2 = 参数错误或运行错误（含任一地址拉取失败）
 *
 * @module lib/batch
 */

import { readFileSync } from 'node:fs';
import { summarizeResults } from './report.mjs';

const TOOL = 'header-forge';

/** 每个待校验项的归类 */
export const BATCH_STATUS = {
  /** 与策略完全一致 */
  consistent: 'consistent',
  /** 能取到响应，但存在缺失或取值不符 */
  inconsistent: 'inconsistent',
  /** 取不到响应（网络/超时/残缺响应）—— 属于运行错误，不是"不合规" */
  error: 'error',
};

/**
 * 解析 `--paths` 的原始取值
 *
 * 支持的形态（三者可混用、可重复给出，顺序即校验顺序）：
 *   --paths /,/admin,/api         逗号分隔（也接受换行分隔）
 *   --paths @paths.txt            从文件读：一行一条，`#` 开头为注释，空行忽略
 *   --paths https://a.example/x   直接给完整 URL（不受 --url 基准影响）
 *
 * 为什么用 `@文件` 而不是再发明一个 `--paths-file`：一个选项一种语义更好记，
 * 而且 `@` 在命令行里不会与真实路径冲突（路径本身不可能以 `@` 开头）。
 *
 * @param {string[]} values 重复给出的 `--paths` 值
 * @returns {Array<{raw: string, source: string}>}
 * @throws {Error} 文件读不到 / 没有任何条目
 */
export function collectPathEntries(values) {
  const entries = [];

  for (const value of values || []) {
    const text = String(value);

    if (text.startsWith('@')) {
      const filePath = text.slice(1).trim();
      if (!filePath) throw new Error('--paths @文件 的写法需要给出文件名');

      let fileText;
      try {
        fileText = readFileSync(filePath, 'utf8');
      } catch (err) {
        throw new Error(`无法读取 --paths 的文件 ${filePath}：${err.message}`);
      }

      for (const line of fileText.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        entries.push({ raw: trimmed, source: filePath });
      }
      continue;
    }

    /* 逗号与换行都当分隔符：从别处粘一列路径进来时两种都可能 */
    for (const part of text.split(/[,\r\n]/)) {
      const trimmed = part.trim();
      if (!trimmed) continue;
      entries.push({ raw: trimmed, source: '--paths' });
    }
  }

  if (entries.length === 0) {
    throw new Error('--paths 没有解析出任何地址（检查是否只写了逗号/空行）');
  }

  return entries;
}

/**
 * 把 `--paths` 的条目解析成完整 URL
 *
 * 完整 URL（http/https）原样使用；否则以 `--url`（或策略里的 primary target）为基准拼接。
 * 没有基准地址时相对路径是**错误**而不是"猜一个" —— 校验错地址比不校验更危险。
 *
 * @param {Array<{raw: string, source: string}>} entries
 * @param {string|null} base
 * @returns {Array<{url: string, raw: string, source: string}>}
 */
export function resolveTargets(entries, base) {
  const out = [];
  let baseUrl = null;

  if (base) {
    try {
      baseUrl = new URL(base);
    } catch {
      throw new Error(`--url 不是合法地址：${base}`);
    }
  }

  for (const entry of entries) {
    if (/^https?:\/\//i.test(entry.raw)) {
      out.push({ ...entry, url: entry.raw });
      continue;
    }
    if (!baseUrl) {
      throw new Error(
        `「${entry.raw}」是相对路径，但没有基准地址 —— 请用 --url 给出基准（或直接写完整 URL）`
      );
    }
    let resolved;
    try {
      resolved = new URL(entry.raw, baseUrl).toString();
    } catch {
      throw new Error(`无法把「${entry.raw}」拼到基准地址 ${base} 上`);
    }
    out.push({ ...entry, url: resolved });
  }

  return out;
}

/**
 * 归类单条校验结果
 *
 * @param {{ok: boolean, error?: string, results: Array<object>, meta: object}} result verifyUrl 的返回
 * @returns {{status: string, error: string|null, summary: object|null}}
 */
export function classifyVerifyResult(result) {
  if (!result || !result.ok) {
    return {
      status: BATCH_STATUS.error,
      error: (result && result.error) || 'UNKNOWN',
      summary: null,
    };
  }

  const { passed, failed, missing, extra } = summarizeResults(result.results);
  const consistent = failed.length === 0 && missing.length === 0;

  return {
    status: consistent ? BATCH_STATUS.consistent : BATCH_STATUS.inconsistent,
    error: null,
    summary: {
      required: passed.length + failed.length + missing.length,
      passed: passed.length,
      missing: missing.length,
      mismatched: failed.length,
      extra: extra.length,
    },
  };
}

/**
 * 汇总一批结果
 * @param {Array<{status: string}>} entries
 */
export function summarizeBatch(entries) {
  const summary = {
    total: entries.length,
    consistent: 0,
    inconsistent: 0,
    errors: 0,
  };

  for (const entry of entries) {
    if (entry.status === BATCH_STATUS.consistent) summary.consistent += 1;
    else if (entry.status === BATCH_STATUS.inconsistent) summary.inconsistent += 1;
    else summary.errors += 1;
  }

  return summary;
}

/**
 * 批量校验的退出码
 *
 * 「运行错误」优先于「不一致」：拉不到响应时我们**不知道**合规不合规，
 * 报 1（不一致）会把"没测到"说成"测出来不合规" —— 那是另一种失败方式。
 *
 * @returns {0|1|2}
 */
export function exitCodeForBatch(summary) {
  if (summary.errors > 0) return 2;
  if (summary.inconsistent > 0) return 1;
  return 0;
}

/** 控制台摘要（逐条 + 汇总） */
export function renderBatchSummary({ entries, base }) {
  const lines = [];
  lines.push(`🔍 批量校验 ${entries.length} 个地址${base ? `（基准 ${base}）` : ''}`);
  lines.push('');

  const width = String(entries.length).length;
  for (const [i, entry] of entries.entries()) {
    const index = String(i + 1).padStart(width);
    const label = `[${index}/${entries.length}] ${entry.url}`;

    if (entry.status === BATCH_STATUS.consistent) {
      lines.push(`${label}  ✅ 一致（符合 ${entry.summary.passed}）`);
    } else if (entry.status === BATCH_STATUS.inconsistent) {
      const parts = [];
      if (entry.summary.missing) parts.push(`缺失 ${entry.summary.missing}`);
      if (entry.summary.mismatched) parts.push(`值不符 ${entry.summary.mismatched}`);
      lines.push(`${label}  ❌ 不一致（${parts.join(' / ')}）`);
      for (const item of entry.results.filter((r) => r.status === 'missing' || r.status === 'mismatch')) {
        lines.push(
          item.status === 'missing'
            ? `        - [缺失] ${item.name}（应设为 ${item.expected}）`
            : `        - [不符] ${item.name}：实际 ${item.actual} / 期望 ${item.expected}`
        );
      }
    } else {
      lines.push(`${label}  ⚠️ 错误：${entry.error}（无法获取响应，未作判定）`);
    }
  }

  const summary = summarizeBatch(entries);
  lines.push('');
  lines.push(
    `汇总：共 ${summary.total} 项 · ✅ 一致 ${summary.consistent} · ` +
      `❌ 不一致 ${summary.inconsistent} · ⚠️ 错误 ${summary.errors}`
  );

  return lines.join('\n');
}

/** 批量 Markdown 报告 */
export function renderBatchMarkdown({ policy, entries, base, meta }) {
  const summary = summarizeBatch(entries);
  const lines = [];

  lines.push('# 安全响应头批量一致性报告');
  lines.push('');
  lines.push(`> 由 \`${TOOL} v${meta.version}\` 于 ${meta.startedAt} 生成`);
  lines.push('');
  lines.push(`- 基准地址：${base || '（未给出，全部使用完整 URL）'}`);
  lines.push(`- 策略文件：\`${meta.policyPath}\``);
  lines.push(`- 校验地址数：${summary.total}`);
  lines.push('');

  lines.push('## 汇总');
  lines.push('');
  lines.push('| 结果 | 数量 |');
  lines.push('| :--- | ---: |');
  lines.push(`| ✅ 一致 | ${summary.consistent} |`);
  lines.push(`| ❌ 不一致 | ${summary.inconsistent} |`);
  lines.push(`| ⚠️ 错误（未作判定） | ${summary.errors} |`);
  lines.push('');

  const verdict =
    summary.errors > 0
      ? `**结论：⚠️ 有 ${summary.errors} 个地址无法校验（运行错误），本次不作合规判定**`
      : summary.inconsistent > 0
        ? `**结论：❌ 有 ${summary.inconsistent} 个地址与策略不一致**`
        : '**结论：✅ 全部地址均符合策略**';
  lines.push(verdict);
  lines.push('');

  lines.push('## 逐条结果');
  lines.push('');
  for (const entry of entries) {
    const icon =
      entry.status === BATCH_STATUS.consistent
        ? '✅ 一致'
        : entry.status === BATCH_STATUS.inconsistent
          ? '❌ 不一致'
          : '⚠️ 错误';
    lines.push(`### ${entry.url}`);
    lines.push('');
    lines.push(`- 结果：${icon}`);
    if (entry.source && entry.source !== '--paths') lines.push(`- 来源：\`${entry.source}\``);
    if (entry.status === BATCH_STATUS.consistent) {
      lines.push(`- 符合 ${entry.summary.passed} 项`);
    } else if (entry.status === BATCH_STATUS.inconsistent) {
      lines.push(
        `- 符合 ${entry.summary.passed} · 缺失 ${entry.summary.missing} · 值不符 ${entry.summary.mismatched}`
      );
      for (const item of entry.results.filter((r) => r.status === 'missing' || r.status === 'mismatch')) {
        lines.push(
          item.status === 'missing'
            ? `  - [缺失] \`${item.name}\`（应设为 \`${item.expected}\`）`
            : `  - [不符] \`${item.name}\`：实际 \`${item.actual}\` / 期望 \`${item.expected}\` —— ${item.note}`
        );
      }
    } else {
      lines.push(`- 错误：${entry.error}`);
      lines.push('- 说明：无法获取响应，因此**不作合规判定**（不要把它当成"不合规"，也不要当成"通过"）');
    }
    lines.push('');
  }

  lines.push('---');
  lines.push('');
  lines.push(
    `<sub>${TOOL} v${meta.version} · 零依赖 · 退出码：0 全部一致 / 1 存在不一致 / 2 参数或运行错误</sub>`
  );

  return lines.join('\n');
}

/** 批量 JSON 报告（`mode: 'batch'` 与单 URL 形态区分） */
export function renderBatchJson({ policy, entries, base, meta }) {
  const summary = summarizeBatch(entries);

  return {
    tool: TOOL,
    version: meta.version,
    mode: 'batch',
    startedAt: meta.startedAt,
    base: base || null,
    policyPath: meta.policyPath,
    policyHeaders: Object.keys(policy.headers),
    compliant: summary.errors === 0 && summary.inconsistent === 0,
    summary,
    entries: entries.map((entry) => ({
      url: entry.url,
      raw: entry.raw,
      source: entry.source,
      status: entry.status,
      error: entry.error,
      status_code: entry.statusCode ?? null,
      finalUrl: entry.finalUrl ?? null,
      ms: entry.ms ?? null,
      summary: entry.summary,
      details: entry.results || [],
    })),
  };
}
