/**
 * 本地模拟器
 *
 * 解决的问题：怎么在不买域名、不部署的前提下，证明「生成的配置确实能达到策略要求」？
 *
 * 做法：**解析生成出来的配置文件**（而不是复用策略对象），把其中的响应头应用到
 * 一个本地静态服务上，再用同一个校验器去校验它。
 *
 * 这样验证链条是完整的：
 *   策略 → 生成器 → 配置文件（真实产物） → 应用到 HTTP 响应 → 校验器 → 一致性通过
 * 如果生成器把值写错了、写漏了、转义错了，这里都会暴露。
 *
 * @module simulate
 */

import http from 'node:http';
import { parseHeadersFile, resolveHeadersForPath } from './generators/headers-file.mjs';

const DEMO_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>header-forge 本地模拟</title></head>
<body><h1>header-forge 本地模拟服务</h1>
<p>本页面用于验证生成的响应头配置是否与策略一致。</p></body>
</html>
`;

/**
 * 从生成的配置文件里解析出响应头
 * 支持两种产物：`_headers`（Cloudflare Pages / Netlify）与 `vercel.json`
 *
 * @param {string} content 配置文件内容
 * @param {string} [path='/'] 用于路径匹配
 * @returns {Record<string,string>}
 */
export function parseGeneratedConfig(content, path = '/') {
  const text = String(content || '').trim();

  if (text.startsWith('{')) {
    const config = JSON.parse(text);
    const out = {};
    for (const rule of config.headers || []) {
      for (const h of rule.headers || []) {
        out[h.key] = h.value;
      }
    }
    return out;
  }

  return resolveHeadersForPath(text, path);
}

/**
 * 启动模拟服务
 *
 * @param {object} options
 * @param {string} options.configText 生成的配置文件内容
 * @param {string} [options.html] 返回的页面内容
 * @param {number} [options.port=0] 0 表示随机端口
 * @returns {Promise<{url: string, headers: Record<string,string>, close: Function}>}
 */
export async function startSimulator(options) {
  const headers = parseGeneratedConfig(options.configText, options.path || '/');
  const html = options.html || DEMO_HTML;

  const server = http.createServer((req, res) => {
    /* 只对匹配路径应用配置；这里模拟静态站点，所有路径都返回页面 */
    const responseHeaders = { 'Content-Type': 'text/html; charset=utf-8', ...resolvedFor(req.url) };
    res.writeHead(200, responseHeaders);
    res.end(html);
  });

  function resolvedFor(url) {
    return parseHeadersForRequest(options.configText, url);
  }

  await new Promise((resolve) => server.listen(options.port ?? 0, '127.0.0.1', resolve));

  const port = server.address().port;
  return {
    url: `http://127.0.0.1:${port}/`,
    headers,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

/** 针对某个请求路径解析配置中的响应头 */
export function parseHeadersForRequest(configText, url) {
  const text = String(configText || '').trim();
  if (text.startsWith('{')) {
    return parseGeneratedConfig(text, '/');
  }
  const path = url === '/' ? '/' : String(url).split('?')[0];
  return resolveHeadersForPath(text, path);
}
