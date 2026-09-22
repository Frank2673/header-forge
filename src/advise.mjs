/**
 * CSP 顾问
 *
 * CSP 是安全响应头里最容易「配了就坏站」的一个：写太严，页面脚本全被拦；
 * 写太松（'unsafe-inline'）等于没写。所以本模块先分析页面的真实资源需求，
 * 再给出一个「既严格又不会破坏站点」的起点策略。
 *
 * 亮点：对页面里的内联脚本自动计算 SHA-256 hash，用 'sha256-...' 代替 'unsafe-inline'。
 * 这是 CSP 里最实用的一招 —— 既保留严格策略，又不牺牲首屏体验（防闪烁脚本必须内联）。
 *
 * @module advise
 */

import { createHash } from 'node:crypto';

/** 这些 script type 是数据块而非可执行脚本，CSP 不拦截它们，也不应计入内联脚本 */
const NON_EXECUTABLE_SCRIPT_TYPES = [
  'application/ld+json',
  'application/json',
  'text/template',
  'text/x-template',
  'importmap',
];

/**
 * 计算 CSP hash（sha256-<base64>）
 */
export function cspHash(content, algorithm = 'sha256') {
  return `${algorithm}-${createHash(algorithm).update(content, 'utf8').digest('base64')}`;
}

/** 抽取可执行的内联脚本块 */
export function extractInlineScripts(html) {
  const blocks = [];
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(String(html))) !== null) {
    const attrs = m[1] || '';
    const body = m[2] || '';

    if (/\bsrc\s*=/i.test(attrs)) continue; // 外链脚本，走 'self' / 来源白名单

    const typeMatch = attrs.match(/\btype\s*=\s*["']([^"']+)["']/i);
    const type = typeMatch ? typeMatch[1].trim().toLowerCase() : 'text/javascript';
    if (NON_EXECUTABLE_SCRIPT_TYPES.includes(type)) continue;

    if (!body.trim()) continue;

    blocks.push({
      type,
      content: body,
      hash: cspHash(body),
      preview: body.trim().split('\n')[0].slice(0, 60),
    });
  }
  return blocks;
}

/** 抽取内联样式块 */
export function extractInlineStyles(html) {
  const blocks = [];
  const re = /<style\b[^>]*>([\s\S]*?)<\/style>/gi;
  let m;
  while ((m = re.exec(String(html))) !== null) {
    const body = m[1] || '';
    if (!body.trim()) continue;
    blocks.push({ content: body, hash: cspHash(body) });
  }
  return blocks;
}

/** 从指定标签的指定属性里提取 URL（必须按标签类型提取，否则会把 <a href> 当成样式表） */
function collectFromTags(html, tags, attr, filter = null) {
  const out = [];
  for (const tag of tags) {
    const tagRe = new RegExp(`<${tag}\\b([^>]*)>`, 'gi');
    let m;
    while ((m = tagRe.exec(html)) !== null) {
      const attrs = m[1] || '';
      if (filter && !filter(attrs)) continue;
      const attrMatch = attrs.match(new RegExp(`\\b${attr}\\s*=\\s*["']([^"']+)["']`, 'i'));
      if (attrMatch) out.push(attrMatch[1].trim());
    }
  }
  return out;
}

/** 从 CSS 文本中提取 url(...) 引用的来源 */
function collectFromCss(cssText, directive) {
  const out = [];
  const re = /url\(\s*["']?([^"')]+)["']?\s*\)/gi;
  let m;
  while ((m = re.exec(String(cssText))) !== null) {
    const origin = toOrigin(m[1].trim());
    if (origin) out.push(origin);
  }
  return out;
}

/**
 * 从句内脚本里提取网络请求目标（fetch / XHR / WebSocket）
 * 这些需要写进 connect-src，漏了会导致运行时请求被 CSP 拦截
 */
function collectConnectTargets(scripts) {
  const out = [];
  for (const script of scripts) {
    const code = script.content;
    const patterns = [
      /\bfetch\(\s*["']([^"']+)["']/gi,
      /\bnew\s+WebSocket\(\s*["']([^"']+)["']/gi,
      /\bnew\s+EventSource\(\s*["']([^"']+)["']/gi,
      /\.open\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']/gi,
    ];
    for (const re of patterns) {
      let m;
      while ((m = re.exec(code)) !== null) {
        const origin = toOrigin(m[1].trim());
        if (origin) out.push(origin);
      }
    }
  }
  return out;
}

/** 从一段 HTML 中提取资源来源与内联使用情况 */
export function analyzePage(html) {
  const text = String(html || '');
  const origins = {
    'script-src': new Set(),
    'style-src': new Set(),
    'img-src': new Set(),
    'font-src': new Set(),
    'connect-src': new Set(),
    'frame-src': new Set(),
    'media-src': new Set(),
  };

  const inlineScripts = extractInlineScripts(text);
  const inlineStyles = extractInlineStyles(text);

  const add = (directive, urls) => {
    for (const u of urls) {
      const origin = toOrigin(u);
      if (origin) origins[directive].add(origin);
    }
  };

  /* 脚本：只认 <script src> */
  add('script-src', collectFromTags(text, ['script'], 'src'));

  /* 样式：只认 <link rel=stylesheet> 与 <link rel=preload as=style> */
  add(
    'style-src',
    collectFromTags(text, ['link'], 'href', (attrs) =>
      /rel\s*=\s*["']stylesheet["']/i.test(attrs) ||
      (/rel\s*=\s*["']preload["']/i.test(attrs) && /as\s*=\s*["']style["']/i.test(attrs))
    )
  );
  add('style-src', collectFromCss(inlineStyles.map((s) => s.content).join('\n')));

  /* 图片：<img src> / <img srcset> / <source src> */
  add('img-src', collectFromTags(text, ['img'], 'src'));
  add('img-src', collectFromTags(text, ['source'], 'src'));

  /* 字体：<link rel=preload as=font> */
  add(
    'font-src',
    collectFromTags(text, ['link'], 'href', (attrs) =>
      /rel\s*=\s*["']preload["']/i.test(attrs) && /as\s*=\s*["']font["']/i.test(attrs)
    )
  );
  add('font-src', collectFromCss(inlineStyles.map((s) => s.content).join('\n')));

  /* 网络请求：从句内脚本中提取 */
  add('connect-src', collectConnectTargets(inlineScripts));

  /* 框架与媒体 */
  add('frame-src', collectFromTags(text, ['iframe'], 'src'));
  add('media-src', collectFromTags(text, ['video', 'audio', 'source'], 'src'));

  /* 内联事件属性（onclick 等）：hash 对它们无效，必须用 'unsafe-inline' 或重构 */
  const eventHandlers = (text.match(/\son[a-z]+\s*=\s*["']/gi) || []).length;
  const styleAttributes = (text.match(/\sstyle\s*=\s*["']/gi) || []).length;
  const remoteScripts = (text.match(/<script\b[^>]*\bsrc\s*=/gi) || []).length;

  return {
    inlineScriptCount: inlineScripts.length,
    inlineScripts,
    inlineStyleCount: inlineStyles.length,
    inlineStyles,
    eventHandlers,
    styleAttributes,
    remoteScripts,
    origins: Object.fromEntries(Object.entries(origins).map(([k, v]) => [k, [...v].sort()])),
  };
}

/** 把 URL 归一化成 CSP 里的来源表达式 */
function toOrigin(url) {
  if (url.startsWith('//')) return null;
  if (url.startsWith('/') || url.startsWith('./') || url.startsWith('../')) return null;
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/**
 * 根据页面分析结果给出 CSP 建议
 * @param {object} analysis analyzePage 的返回值
 * @param {object} options
 * @param {boolean} [options.useHashes=true] 用 hash 代替 'unsafe-inline'（推荐）
 * @param {boolean} [options.reportOnly=false] 提示先观察
 */
export function suggestCsp(analysis, options = {}) {
  const { useHashes = true, reportOnly = false } = options;
  const warnings = [];
  const notes = [];
  const directives = {};

  directives['default-src'] = "'self'";

  /* ---- script-src ---- */
  const scriptParts = ["'self'", ...analysis.origins['script-src']];
  /* 对外返回不带引号的原始 hash，拼进指令时才加单引号（避免调用方重复加引号） */
  const hashes = analysis.inlineScripts.map((s) => s.hash);

  if (analysis.inlineScripts.length > 0) {
    if (useHashes) {
      scriptParts.push(...hashes.map((h) => `'${h}'`));
      notes.push(
        `已为 ${analysis.inlineScripts.length} 段内联脚本计算 hash（${hashes.length} 条），` +
          '无需放行 unsafe-inline —— 修改内联脚本后必须重新生成策略'
      );
    } else {
      scriptParts.push("'unsafe-inline'");
      warnings.push("选择使用 'unsafe-inline'：任何注入的脚本都能执行，CSP 防护大打折扣");
    }
  }

  if (analysis.eventHandlers > 0) {
    scriptParts.push("'unsafe-inline'");
    warnings.push(
      `页面存在 ${analysis.eventHandlers} 处内联事件属性（onclick 等）：hash 对它们无效，` +
        "只能放行 'unsafe-inline'。建议改为 addEventListener（这是唯一彻底的解法）。"
    );
  }
  directives['script-src'] = scriptParts.join(' ');

  /* ---- style-src ---- */
  const styleParts = ["'self'", ...analysis.origins['style-src']];
  if (analysis.inlineStyles.length > 0) {
    if (useHashes) {
      styleParts.push(...analysis.inlineStyles.map((s) => `'${s.hash}'`));
      notes.push(`已为 ${analysis.inlineStyles.length} 段内联样式计算 hash`);
    } else {
      styleParts.push("'unsafe-inline'");
    }
  }
  if (analysis.styleAttributes > 0) {
    styleParts.push("'unsafe-inline'");
    notes.push(
      `页面含 ${analysis.styleAttributes} 处 style 属性：style-src 需放行 'unsafe-inline'` +
        '（样式注入风险远低于脚本，通常可接受）'
    );
  }
  directives['style-src'] = dedupe(styleParts).join(' ');

  /* ---- 其余资源类指令 ---- */
  directives['img-src'] = dedupe(["'self'", 'data:', ...analysis.origins['img-src']]).join(' ');
  directives['font-src'] = dedupe(["'self'", 'data:', ...analysis.origins['font-src']]).join(' ');
  directives['connect-src'] = dedupe(["'self'", ...analysis.origins['connect-src']]).join(' ');

  if (analysis.origins['frame-src'].length) {
    directives['frame-src'] = analysis.origins['frame-src'].join(' ');
  }
  if (analysis.origins['media-src'].length) {
    directives['media-src'] = analysis.origins['media-src'].join(' ');
  }

  /* ---- 加固类指令（无兼容性风险） ---- */
  directives['frame-ancestors'] = "'none'";
  directives['base-uri'] = "'self'";
  directives['form-action'] = "'self'";
  directives['object-src'] = "'none'";
  directives['upgrade-insecure-requests'] = '';

  if (analysis.remoteScripts === 0 && analysis.origins['script-src'].length === 0) {
    notes.push('未发现第三方脚本，CSP 白名单可保持最小');
  } else if (analysis.origins['script-src'].length > 0) {
    notes.push(`检测到第三方脚本来源：${analysis.origins['script-src'].join(', ')}`);
  }
  if (reportOnly) {
    notes.push('建议先以 Content-Security-Policy-Report-Only 上线观察，确认真实流量无违规后再切换为强制模式');
  }

  const value = Object.entries(directives)
    .map(([k, v]) => (v ? `${k} ${v}` : k))
    .join('; ');

  return { value, directives, warnings, notes, hashes };
}

/**
 * 检查策略中的 CSP hash 是否与页面当前内容一致（防止「改了脚本忘了改策略」）
 * @param {object} policy
 * @param {object} analysis
 * @returns {{consistent: boolean, missingInPolicy: string[], staleInPolicy: string[]}}
 */
export function checkHashDrift(policy, analysis) {
  const cspHeader = policy.headers['Content-Security-Policy'];
  if (!cspHeader) {
    return { consistent: false, missingInPolicy: [], staleInPolicy: [], reason: '策略中没有 CSP' };
  }

  const inPolicy = new Set((cspHeader.value.match(/'sha256-[A-Za-z0-9+/=]+'/g) || []).map((s) => s.slice(1, -1)));
  const inPage = new Set([
    ...analysis.inlineScripts.map((s) => s.hash),
    ...analysis.inlineStyles.map((s) => s.hash),
  ]);

  const missingInPolicy = [...inPage].filter((h) => !inPolicy.has(h));
  const staleInPolicy = [...inPolicy].filter((h) => !inPage.has(h));

  return {
    consistent: missingInPolicy.length === 0 && staleInPolicy.length === 0,
    missingInPolicy,
    staleInPolicy,
  };
}

function dedupe(list) {
  return [...new Set(list.filter(Boolean))];
}
