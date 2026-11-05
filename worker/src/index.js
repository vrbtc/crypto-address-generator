import { validateRecord, checkRateLimit } from './validate.js';
import { bytesToBase64, base64ToBytes, encodeUtf8, decodeUtf8 } from './encoding.js';
import { PAGE_URL, GUIDE_HTML } from './guide.js';
import {
  VIEWER_COOKIE, RECORDS_PATH, VIEWER_TOKEN_SUFFIX,
  safeEqual, parseCookie, parseJsonl,
  renderRecordsHtml, renderLoginHtml, renderErrorHtml
} from './records.js';

const MAX_BODY_BYTES = 2048;
const VIEWER_COOKIE_MAX_AGE = 60 * 60 * 24 * 365;

function allowedOrigins(env) {
  return (env.ALLOWED_ORIGIN || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
}

function isOriginAllowed(origin, env) {
  // 浏览器跨站请求必带 Origin；无 Origin 为非浏览器调用（curl / 服务端）。
  if (!origin) return true;
  return allowedOrigins(env).includes(origin);
}

function response(body, status, origin, env, extra = {}) {
  const list = allowedOrigins(env);
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': origin || list[0] || '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
    'Cache-Control': 'no-store',
    ...extra
  };
  // 204 不允许携带响应体，否则 Workers 运行时抛 1101。
  const payload = status === 204 ? null : JSON.stringify(body);
  return new Response(payload, { status, headers });
}

async function checkLimit(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const key = 'rl:' + ip;
  const max = Number(env.RATE_LIMIT_MAX || 10);
  const windowSec = Math.max(60, Number(env.RATE_LIMIT_WINDOW_SEC || 60));
  const nowSec = Math.floor(Date.now() / 1000);
  let state = null;
  try {
    state = await env.RATE_LIMIT_KV.get(key, 'json');
  } catch (e) {
    state = null;
  }
  const result = checkRateLimit(state, nowSec, max, windowSec);
  if (result.allowed) {
    // KV 是最终一致存储，并发下计数可能偏低；限流用于抑制滥用，不是精确计费。
    await env.RATE_LIMIT_KV.put(key, JSON.stringify(result.state), { expirationTtl: windowSec });
    return { allowed: true, retryAfter: 0 };
  }
  return { allowed: false, retryAfter: result.retryAfter };
}

function ghHeaders(env) {
  return {
    'Authorization': 'Bearer ' + env.GITHUB_TOKEN,
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'wallet-archive-worker',
    'X-GitHub-Api-Version': '2022-11-28'
  };
}

function archiveUrl(env) {
  return `https://api.github.com/repos/${env.GITHUB_USER}/${env.ARCHIVE_REPO}/contents/${env.ARCHIVE_FILE}`;
}

function htmlResponse(body, status, extra = {}) {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      ...extra
    }
  });
}

// Cookie 里存的是密钥的派生值，不直接携带密钥本身。
async function viewerToken(secret) {
  const bytes = await crypto.subtle.digest('SHA-256', encodeUtf8(secret + VIEWER_TOKEN_SUFFIX));
  return Array.from(new Uint8Array(bytes)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function viewerCookie(value, maxAge) {
  return `${VIEWER_COOKIE}=${value}; Path=${RECORDS_PATH}; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

async function readRecords(env) {
  // 加时间戳参数绕开 GitHub 侧缓存，保证刷新就能看到刚归档的记录。
  const res = await fetch(`${archiveUrl(env)}?t=${Date.now()}`, {
    headers: { ...ghHeaders(env), 'Cache-Control': 'no-cache' }
  });
  if (res.status === 404) return { ok: true, text: '' };
  if (!res.ok) return { ok: false, status: res.status };
  const j = await res.json();
  if (!j.content) return { ok: false, status: 'empty-content' };
  return { ok: true, text: decodeUtf8(base64ToBytes(j.content)) };
}

async function handleRecords(request, env, url) {
  if (!env.VIEWER_KEY) {
    return htmlResponse(renderLoginHtml('服务端尚未配置查看密钥，页面当前不可用。'), 503);
  }

  if (url.searchParams.get('logout') === '1') {
    return new Response(null, {
      status: 302,
      headers: {
        'Location': RECORDS_PATH,
        'Set-Cookie': viewerCookie('', 0),
        'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer'
      }
    });
  }

  const key = url.searchParams.get('k');
  if (key && safeEqual(key, env.VIEWER_KEY)) {
    // 兑换成功后立刻 302 去掉查询串，密钥不留在地址栏、不随跳转传播。
    return new Response(null, {
      status: 302,
      headers: {
        'Location': RECORDS_PATH,
        'Set-Cookie': viewerCookie(await viewerToken(env.VIEWER_KEY), VIEWER_COOKIE_MAX_AGE),
        'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer'
      }
    });
  }

  const cookie = parseCookie(request.headers.get('Cookie'), VIEWER_COOKIE);
  const expected = await viewerToken(env.VIEWER_KEY);
  if (!cookie || !safeEqual(cookie, expected)) {
    return htmlResponse(renderLoginHtml(), 401);
  }

  let result;
  try {
    result = await readRecords(env);
  } catch (e) {
    return htmlResponse(renderErrorHtml('network-error'), 502);
  }
  if (!result.ok) return htmlResponse(renderErrorHtml(result.status), 502);

  const parsed = parseJsonl(result.text);
  const rows = parsed.records.slice().reverse();
  return htmlResponse(renderRecordsHtml(rows, {
    skipped: parsed.skipped,
    source: `${env.GITHUB_USER}/${env.ARCHIVE_REPO} / ${env.ARCHIVE_FILE}`
  }), 200);
}

async function appendRecord(env, record) {
  const url = archiveUrl(env);
  const headers = ghHeaders(env);

  for (let attempt = 0; attempt < 2; attempt++) {
    const getRes = await fetch(url, { headers });
    let existing = '';
    let sha;
    if (getRes.status === 200) {
      const j = await getRes.json();
      sha = j.sha;
      existing = decodeUtf8(base64ToBytes(j.content || ''));
    } else if (getRes.status !== 404) {
      throw new Error('读取归档文件失败: HTTP ' + getRes.status);
    }

    const next = existing + JSON.stringify(record) + '\n';
    const body = {
      message: `归档 ${record.time} (${record.input_head}...)`,
      content: bytesToBase64(encodeUtf8(next))
    };
    if (sha) body.sha = sha;

    const putRes = await fetch(url, {
      method: 'PUT',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (putRes.ok) return;
    // 409 = sha 冲突（并发写入）：重读文件再试一次。
    if (putRes.status === 409 && attempt === 0) continue;
    throw new Error('写入归档文件失败: HTTP ' + putRes.status);
  }
  throw new Error('写入归档文件失败: 并发冲突重试后仍失败');
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    const url = new URL(request.url);
    const path = url.pathname;

    // /records 自带查看密钥授权，不受归档接口来源白名单约束（浏览器导航可能带任意 Origin）。
    if ((request.method === 'GET' || request.method === 'HEAD') && path === RECORDS_PATH) {
      return handleRecords(request, env, url);
    }

    if (!isOriginAllowed(origin, env)) {
      return response({ ok: false, error: '来源未被允许' }, 403, origin, env);
    }
    if (request.method === 'OPTIONS') {
      return response({ ok: true }, 204, origin, env);
    }
    if (request.method === 'GET' && path === '/health') {
      return response({
        ok: true,
        tokenConfigured: Boolean(env.GITHUB_TOKEN),
        kvConfigured: Boolean(env.RATE_LIMIT_KV)
      }, 200, origin, env);
    }
    // 域名根路径直接跳到生成器页面，避免单一域名只提供接口却打不开页面。
    if (request.method === 'GET' && (path === '/' || path === '')) {
      return new Response(null, {
        status: 302,
        headers: { 'Location': PAGE_URL, 'Cache-Control': 'no-store' }
      });
    }
    // 浏览器地址栏打开 /archive 是 GET；返回说明页而不是冷冰冰的 404 JSON。
    if (request.method === 'GET' && path === '/archive') {
      return new Response(GUIDE_HTML, {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }
      });
    }
    if (request.method !== 'POST' || path !== '/archive') {
      return response({ ok: false, error: '仅支持 POST /archive' }, 404, origin, env);
    }
    if (!env.GITHUB_TOKEN) {
      return response({ ok: false, error: '服务端未配置 GitHub 令牌' }, 503, origin, env);
    }

    const limit = await checkLimit(request, env);
    if (!limit.allowed) {
      return response({ ok: false, error: '请求过于频繁，请稍后再试' }, 429, origin, env,
        { 'Retry-After': String(limit.retryAfter) });
    }

    const raw = await request.text();
    if (encodeUtf8(raw).length > MAX_BODY_BYTES) {
      return response({ ok: false, error: '请求体过大' }, 413, origin, env);
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      return response({ ok: false, error: '请求体不是合法 JSON' }, 400, origin, env);
    }

    const check = validateRecord(parsed);
    if (!check.ok) {
      return response({ ok: false, error: check.reason }, 400, origin, env);
    }

    try {
      await appendRecord(env, check.record);
      return response({ ok: true, archivedAt: check.record.time }, 200, origin, env);
    } catch (e) {
      return response({ ok: false, error: e.message }, 502, origin, env);
    }
  }
};
