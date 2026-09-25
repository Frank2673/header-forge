/**
 * SARIF 输出（供 GitHub Code Scanning）
 *
 * SARIF 是让校验结果进入仓库 Security 面板的通用格式。接入后的变化是：
 * 响应头降级不再是"CI 日志里一行红字"，而是一条可指派、可标记、可跟踪修复的告警。
 *
 * ## 三条设计决策（都会直接决定面板好不好用）
 *
 * 1. **哪些问题映射成哪级 level**
 *    `missing`（策略要求但线上没有）与 `mismatch`（有但取值被放宽）都是"真问题"，
 *    按策略里声明的 severity 走统一映射：
 *      critical/high → error ｜ medium → warning ｜ low/info → note
 *    `extra`（线上有、策略未声明的头）**不进 SARIF** —— 它不是违规，
 *    而且站点几乎总会有 `Server` / `X-Powered-By` 这类头，报进来就是永远关不掉的噪音。
 *    拉取失败（拿不到响应）也不进 SARIF：那是"没测到"，不是"代码有问题"，
 *    它由退出码 2 表达（CI 红），不该在面板里伪装成一条安全告警。
 *    两者都保留在 JSON/Markdown 报告与 `run.properties` 里，信息不丢。
 *
 * 2. **ruleId 怎么稳定命名**
 *    `header-forge/<状态>/<头名小写短横线>`，例如 `header-forge/missing/referrer-policy`。
 *    **绝不含 URL** —— 否则同一类问题在 10 个路径上就是 10 条规则，面板会被刷爆。
 *    反向地，`missing` 与 `mismatch` 是两类问题，分成两条规则让面板能分别统计。
 *
 * 3. **partialFingerprints 用什么做去重键**
 *    `sha256(状态 | URL | 头名)` —— 只由"同一个问题是什么"决定，
 *    **不含实际值、期望值、时间戳、运行序号**。这是关键：
 *    站点把 `max-age` 从 600 改成 300 时，问题是"同一个问题"（HSTS 取值不符），
 *    指纹必须不变，否则每跑一次 CI 就新开一条告警、旧的那条永远悬着。
 *
 * @module lib/sarif
 */

import { createHash } from 'node:crypto';

const TOOL = 'header-forge';
const SARIF_VERSION = '2.1.0';
const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const FINGERPRINT_KEY = 'headerForgeFingerprint/v1';

/** 策略 severity → SARIF level */
const LEVEL_MAP = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

/** 策略 severity → GitHub Security 面板排序用的分值 */
const SECURITY_SEVERITY_MAP = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
  info: '1.0',
};

/**
 * 把单 URL 的校验结果包装成与批量模式一致的 entry 形态
 * （这样 SARIF 生成只认一种输入，不必分叉）
 */
export function entryFromSingle({ url, results, meta = {} }) {
  const failed = results.filter((r) => r.status === 'mismatch');
  const missing = results.filter((r) => r.status === 'missing');
  const extra = results.filter((r) => r.status === 'extra');
  const passed = results.filter((r) => r.status === 'pass');

  return {
    url,
    raw: url,
    source: '--url',
    status: failed.length === 0 && missing.length === 0 ? 'consistent' : 'inconsistent',
    error: null,
    summary: {
      required: passed.length + failed.length + missing.length,
      passed: passed.length,
      missing: missing.length,
      mismatched: failed.length,
      extra: extra.length,
    },
    results,
    statusCode: meta.status ?? null,
    finalUrl: meta.finalUrl ?? null,
    ms: meta.ms ?? null,
  };
}

/**
 * 从各 URL 的校验结果里抽出"要上报的问题"
 *
 * 只取 `missing` 与 `mismatch` —— 理由见模块头部的决策 1。
 *
 * @param {Array<object>} entries
 * @returns {Array<{url:string, header:string, status:string, severity:string,
 *                  expected:string|null, actual:string|null, note:string, why:string}>}
 */
export function collectProblems(entries) {
  const problems = [];

  for (const entry of entries) {
    for (const item of entry.results || []) {
      if (item.status !== 'missing' && item.status !== 'mismatch') continue;
      problems.push({
        url: entry.url,
        header: item.name,
        status: item.status,
        severity: item.severity || 'info',
        expected: item.expected ?? null,
        actual: item.actual ?? null,
        note: item.note || '',
        why: item.why || '',
      });
    }
  }

  return problems;
}

/** 问题 → 规则 id（不含 URL；见模块头部决策 2） */
export function ruleIdFor(problem) {
  return `${TOOL}/${problem.status}/${slug(problem.header)}`;
}

/**
 * 问题 → 稳定指纹（见模块头部决策 3）
 *
 * 只由「哪个地址上的哪个头出了哪类问题」决定，运行间恒定。
 */
export function fingerprintFor(problem) {
  const material = `${problem.status}|${problem.url}|${problem.header.toLowerCase()}`;
  return createHash('sha256').update(material, 'utf8').digest('hex');
}

/**
 * 生成 SARIF 2.1.0 文档
 *
 * @param {object} input
 * @param {Array<object>} input.entries 批量形态的校验结果
 * @param {string} input.policyPath 策略文件（SARIF 的 location 指向它 —— 要修的就是这里）
 * @param {string} input.version 工具版本
 * @param {string} [input.toolUri]
 * @param {string} [input.sourceFile] 覆盖 location（默认用 policyPath）
 * @param {string} [input.startedAt]
 * @returns {object} SARIF 文档
 */
export function toSarif({ entries, policyPath, version, toolUri, sourceFile, startedAt }) {
  const problems = collectProblems(entries);
  const rules = buildRules(problems);
  const ruleIndex = new Map(rules.map((rule, i) => [rule.id, i]));
  const location = sourceFile || policyPath || 'headers.policy.json';

  const results = problems.map((problem) => ({
    ruleId: ruleIdFor(problem),
    ruleIndex: ruleIndex.get(ruleIdFor(problem)),
    level: LEVEL_MAP[problem.severity] || 'note',
    message: {
      text:
        `[${problem.header}] ${problem.url}\n` +
        (problem.status === 'missing'
          ? `线上未返回该响应头，策略要求 ${problem.expected}`
          : `线上取值与策略不符：实际 ${problem.actual} / 期望 ${problem.expected}`) +
        (problem.note ? `\n比对说明：${problem.note}` : '') +
        (problem.why ? `\n为什么重要：${problem.why}` : ''),
    },
    locations: [
      {
        physicalLocation: {
          /* 落在策略文件上：响应头缺失/被放宽时，你要改的就是这里（或部署配置）。
             远端 URL 无法成为仓库内位置，因此它保留在 message 与 properties 里。 */
          artifactLocation: { uri: normalizeUri(location) },
          region: { startLine: 1 },
        },
      },
    ],
    partialFingerprints: {
      [FINGERPRINT_KEY]: fingerprintFor(problem),
    },
    properties: {
      url: problem.url,
      header: problem.header,
      status: problem.status,
      severity: problem.severity,
      expected: problem.expected,
      actual: problem.actual,
    },
  }));

  const unreachable = entries
    .filter((e) => e.status === 'error')
    .map((e) => ({ url: e.url, error: e.error }));

  const extras = entries.flatMap((e) =>
    (e.results || [])
      .filter((r) => r.status === 'extra')
      .map((r) => ({ url: e.url, header: r.name, value: r.value ?? r.actual ?? null }))
  );

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: TOOL,
            version: version || '0.0.0',
            informationUri: toolUri || 'https://github.com/Frank2673/header-forge',
            rules,
          },
        },
        invocation: {
          executionSuccessful: unreachable.length === 0,
          ...(startedAt ? { startTimeUtc: startedAt } : {}),
          endTimeUtc: new Date().toISOString(),
        },
        properties: {
          policyPath,
          checkedUrls: entries.map((e) => e.url),
          problemCount: problems.length,
          /* 未上报的两类信息在这里保留：不丢，但也不在面板里制造噪音 */
          unreachable,
          extraHeaders: extras,
        },
        results,
      },
    ],
  };
}

/** 按规则聚合：同一条规则只声明一次 */
function buildRules(problems) {
  const byId = new Map();

  for (const problem of problems) {
    const id = ruleIdFor(problem);
    if (byId.has(id)) continue;

    const level = LEVEL_MAP[problem.severity] || 'note';
    const verb = problem.status === 'missing' ? '未返回' : '取值不符';

    byId.set(id, {
      id,
      name: toRuleName(id),
      shortDescription: { text: `${problem.header} ${verb}（安全响应头）` },
      fullDescription: {
        text:
          problem.status === 'missing'
            ? `线上响应缺少策略要求的 ${problem.header} 响应头`
            : `线上 ${problem.header} 的取值与策略不一致（被放宽）`,
      },
      help: {
        text:
          `检查项：${problem.header}（${problem.status}）\n严重度：${problem.severity}\n\n` +
          `修法：改 headers.policy.json 里该头的取值，走 generate → simulate → 发布；\n` +
          `若线上本来该有却没有，先确认部署配置（_headers / nginx / caddy / .htaccess）真的生效，\n` +
          `再用 verify 复验。`,
        markdown: [
          `**检查项**：\`${problem.header}\`（${problem.status === 'missing' ? '缺失' : '取值不符'}）`,
          '',
          `**严重度**：${problem.severity}`,
          '',
          '**修法**：改 `headers.policy.json` 里该头的取值 → `generate` → `simulate` → 发布；',
          '若线上本该有却没有，先确认部署配置真的生效，再用 `verify` 复验。',
        ].join('\n'),
      },
      defaultConfiguration: { level },
      properties: {
        tags: ['security', 'response-headers', problem.header],
        'security-severity': SECURITY_SEVERITY_MAP[problem.severity] || '1.0',
      },
    });
  }

  return [...byId.values()].sort((a, b) => a.id.localeCompare(b.id));
}

/** 规则 id → 只含字母数字与连字符的规则名 */
function toRuleName(id) {
  return id
    .replace(/[^A-Za-z0-9]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

function slug(name) {
  return String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

/** 路径 → SARIF 的 URI（相对路径按 POSIX 写法，GitHub 才能对上仓库内文件） */
function normalizeUri(p) {
  return String(p).split('\\').join('/');
}

/**
 * 自检：产出的 SARIF 是否满足 SARIF 2.1.0 的必填项与 GitHub 的最低要求
 *
 * 零依赖，因此不引入 schema 校验器 —— 只查"上传后会被 GitHub 拒绝或展示异常"的那些点：
 * 必填字段、level 合法性、ruleId 是否在 rules 里声明、指纹是否存在。
 *
 * @param {object} sarif
 * @returns {{ok: boolean, problems: string[]}}
 */
export function validateSarif(sarif) {
  const problems = [];

  if (!sarif || typeof sarif !== 'object') return { ok: false, problems: ['不是对象'] };
  if (sarif.version !== SARIF_VERSION) problems.push(`version 应为 ${SARIF_VERSION}`);
  if (!sarif.$schema) problems.push('缺少 $schema');
  if (!Array.isArray(sarif.runs) || sarif.runs.length === 0) problems.push('runs 不能为空');

  const run = sarif.runs && sarif.runs[0];
  if (!run) return { ok: false, problems };

  const driver = run.tool && run.tool.driver;
  if (!driver) problems.push('缺少 tool.driver');
  else {
    if (!driver.name) problems.push('缺少 tool.driver.name');
    if (!driver.version) problems.push('缺少 tool.driver.version');
    if (!Array.isArray(driver.rules)) problems.push('缺少 tool.driver.rules 数组');
  }
  if (!Array.isArray(run.results)) problems.push('缺少 results 数组');

  const ruleIds = new Set(((driver && driver.rules) || []).map((r) => r.id));

  for (const [i, rule] of ((driver && driver.rules) || []).entries()) {
    if (!rule.id) problems.push(`rules[${i}] 缺少 id`);
    if (!rule.shortDescription || !rule.shortDescription.text) {
      problems.push(`rules[${i}] 缺少 shortDescription.text`);
    }
    const level = rule.defaultConfiguration && rule.defaultConfiguration.level;
    if (!['error', 'warning', 'note', 'none'].includes(level)) {
      problems.push(`rules[${i}] 的 defaultConfiguration.level 非法：${level}`);
    }
  }

  for (const [i, result] of (run.results || []).entries()) {
    if (!result.ruleId) problems.push(`results[${i}] 缺少 ruleId`);
    else if (!ruleIds.has(result.ruleId)) {
      problems.push(`results[${i}] 的 ruleId「${result.ruleId}」不在 rules 中声明`);
    }
    if (!result.message || !result.message.text) problems.push(`results[${i}] 缺少 message.text`);
    if (!['error', 'warning', 'note', 'none'].includes(result.level)) {
      problems.push(`results[${i}] 的 level 非法：${result.level}`);
    }
    const loc = result.locations && result.locations[0];
    if (!loc || !loc.physicalLocation || !loc.physicalLocation.artifactLocation) {
      problems.push(`results[${i}] 缺少 locations[0].physicalLocation.artifactLocation`);
    } else if (!loc.physicalLocation.artifactLocation.uri) {
      problems.push(`results[${i}] 的 artifactLocation 缺少 uri`);
    }

    /* ruleIndex 必须指向 rules 里对应的那一条（写错会让面板显示错规则） */
    if (typeof result.ruleIndex === 'number' && Array.isArray(driver.rules)) {
      const target = driver.rules[result.ruleIndex];
      if (!target || target.id !== result.ruleId) {
        problems.push(`results[${i}] 的 ruleIndex=${result.ruleIndex} 与 ruleId 不匹配`);
      }
    }

    const fingerprints = result.partialFingerprints;
    if (!fingerprints || typeof fingerprints !== 'object' || Object.keys(fingerprints).length === 0) {
      problems.push(`results[${i}] 缺少 partialFingerprints（面板会反复新增告警）`);
    } else {
      for (const [key, value] of Object.entries(fingerprints)) {
        if (typeof value !== 'string' || value.length === 0) {
          problems.push(`results[${i}] 的 partialFingerprints.${key} 不是非空字符串`);
        }
      }
    }
  }

  return { ok: problems.length === 0, problems };
}

/** SARIF 报告的控制台摘要 */
export function renderSarifSummary({ path, sarif, expectedProblems }) {
  const run = sarif.runs[0];
  const byLevel = { error: 0, warning: 0, note: 0 };
  for (const r of run.results) byLevel[r.level] = (byLevel[r.level] || 0) + 1;

  return [
    `🧾 SARIF 已写入：${path}`,
    `   规则 ${run.tool.driver.rules.length} 条 · 结果 ${run.results.length} 条` +
      `（error ${byLevel.error} / warning ${byLevel.warning} / note ${byLevel.note}）`,
    `   输入问题数 ${expectedProblems} —— 结果数与之${run.results.length === expectedProblems ? '一致' : '不一致（自检失败）'}`,
  ].join('\n');
}
