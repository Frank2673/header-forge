/**
 * 极简 HTTP 客户端（零依赖）
 *
 * 沿用 surface-watch 的一个教训：**绝不能把「被中断的残缺响应」当成功返回**，
 * 否则校验器会基于不完整的响应头得出"头部缺失"的错误结论。
 *
 * @module lib/http
 */

import https from 'node:https';
import http from 'node:http';

const DEFAULT_UA = 'header-forge/0.1 (+security-headers-verification)';
const MAX_BODY_BYTES = 512 * 1024;
const MAX_REDIRECTS = 5;

/**
 * 发起请求；永不 reject，网络问题变成 error 字段
 * @param {string} url
 * @param {object} options
 */
export async function request(url, options = {}) {
  const { method = 'GET', timeoutMs = 10000, retries = 2, headers = {}, followRedirects = true } = options;
  let lastError = null;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await once(url, { method, timeoutMs, headers, followRedirects });
    } catch (err) {
      lastError = err;
      if (err.code === 'TOO_MANY_REDIRECTS') break;
      if (attempt < retries) await new Promise((r) => setTimeout(r, 350 * (attempt + 1)));
    }
  }

  return {
    ok: false,
    error: lastError ? lastError.code || lastError.message : 'UNKNOWN',
    status: null,
    headers: {},
    body: '',
    finalUrl: url,
    ms: 0,
    redirects: [],
  };
}

function once(url, { method, timeoutMs, headers, followRedirects }, redirectCount = 0, chain = []) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const parsed = new URL(url);
    const client = parsed.protocol === 'http:' ? http : https;

    const req = client.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'http:' ? 80 : 443),
        path: parsed.pathname + parsed.search,
        method,
        headers: {
          'User-Agent': DEFAULT_UA,
          Accept: '*/*',
          'Accept-Encoding': 'identity',
          ...headers,
        },
        rejectUnauthorized: false,
        timeout: timeoutMs,
      },
      (res) => {
        if (followRedirects && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          if (redirectCount >= MAX_REDIRECTS) {
            return reject(Object.assign(new Error('重定向次数过多'), { code: 'TOO_MANY_REDIRECTS' }));
          }
          const next = new URL(res.headers.location, url).toString();
          return resolve(
            once(next, { method, timeoutMs, headers, followRedirects }, redirectCount + 1, [
              ...chain,
              { from: url, to: next, status: res.statusCode },
            ])
          );
        }

        const chunks = [];
        let received = 0;
        let sawEnd = false;
        let settled = false;

        res.on('data', (chunk) => {
          received += chunk.length;
          if (received <= MAX_BODY_BYTES) chunks.push(chunk);
          else res.destroy();
        });

        const finish = () => {
          if (settled) return;
          settled = true;
          resolve({
            ok: true,
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
            truncated: received > MAX_BODY_BYTES,
            finalUrl: url,
            redirects: chain,
            ms: Date.now() - started,
          });
        };

        res.on('end', () => {
          sawEnd = true;
          finish();
        });

        /* 提前断开必须判为失败：残缺的响应头会让校验结论失真 */
        res.on('close', () => {
          if (settled) return;
          if (sawEnd) return finish();

          const expected = Number(res.headers['content-length'] || 0);
          if ((!expected || received < expected) && received <= MAX_BODY_BYTES) {
            settled = true;
            reject(
              Object.assign(
                new Error(`响应被提前中断（收到 ${received} 字节，期望 ${expected || '未知'}）`),
                { code: 'INCOMPLETE_RESPONSE' }
              )
            );
            return;
          }
          finish();
        });
      }
    );

    req.on('timeout', () => req.destroy(Object.assign(new Error('请求超时'), { code: 'TIMEOUT' })));
    req.on('error', reject);
    req.end();
  });
}
