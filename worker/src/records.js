// /records 记录查看页：把私有仓库的 records.jsonl 渲染成可直接打开的中文表格。
// 归档接口允许任意来源伪造记录，因此这里所有字段一律当作不可信输入做 HTML 转义。

import { RECORD_FIELDS } from './validate.js';

export const VIEWER_COOKIE = 'wallet_view';
export const RECORDS_PATH = '/records';
export const VIEWER_TOKEN_SUFFIX = '|wallet-viewer-v1';
const MAX_CELL_CHARS = 200;
const ESCAPES = Object.freeze({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
});

// 纯函数：HTML 文本与属性转义。防止伪造记录注入脚本。
export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ESCAPES[ch]);
}

// 纯函数：常量时间字符串比较，避免用响应时间猜密钥。
export function safeEqual(a, b) {
  const x = String(a ?? ''), y = String(b ?? '');
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}

// 纯函数：从 Cookie 请求头里取指定名称的值。
export function parseCookie(header, name) {
  if (!header) return null;
  for (const part of String(header).split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) {
      try { return decodeURIComponent(part.slice(i + 1).trim()); } catch (e) { return null; }
    }
  }
  return null;
}

// 纯函数：解析 JSONL。损坏行、非对象行一律跳过并计数，不让单行坏数据毁掉整页。
export function parseJsonl(text) {
  const records = [];
  let skipped = 0;
  for (const line of String(text ?? '').split(/\r?\n/)) {
    if (!line.trim()) continue;
    let value;
    try { value = JSON.parse(line); } catch (e) { skipped++; continue; }
    if (!value || typeof value !== 'object' || Array.isArray(value)) { skipped++; continue; }
    const row = {};
    for (const field of RECORD_FIELDS) {
      const v = value[field];
      let s = '';
      if (typeof v === 'string') s = v;
      else if (v !== undefined && v !== null) {
        try { s = JSON.stringify(v); } catch (e) { s = String(v); }
      }
      row[field] = s.length > MAX_CELL_CHARS ? s.slice(0, MAX_CELL_CHARS) + '…' : s;
    }
    records.push(row);
  }
  return { records, skipped };
}

// 纯函数：原文片段的展示文本。短原文头尾为空，绝不拼回完整原文。
export function fragmentLabel(head, tail) {
  const h = String(head ?? ''), t = String(tail ?? '');
  if (!h && !t) return '—（短原文，未记录片段）';
  const parts = [];
  if (h) parts.push('前4位 ' + h);
  if (t) parts.push('后4位 ' + t);
  return parts.join(' · ');
}

function cellCode(value, extraClass = '') {
  return `<code class="addr ${extraClass}" title="点击复制">${escapeHtml(value) || '—'}</code>`;
}

// 纯函数：渲染完整 HTML 文档。rows 已按展示顺序排好（最新在前）。
export function renderRecordsHtml(rows, meta = {}) {
  const total = rows.length;
  const skipped = Number(meta.skipped || 0);
  const latest = total ? rows[0].time : '—';
  const source = escapeHtml(meta.source || '私有仓库 wallet-record / records.jsonl');
  const path = RECORDS_PATH;

  const body = rows.map((r, i) => `
      <tr>
        <td class="num">${total - i}</td>
        <td class="time">${escapeHtml(r.time) || '—'}</td>
        <td class="frag"><span class="frag-txt">${escapeHtml(fragmentLabel(r.input_head, r.input_tail))}</span></td>
        <td>${cellCode(r.eth)}</td>
        <td>${cellCode(r.btc_legacy)}</td>
        <td>${cellCode(r.btc_segwit)}</td>
      </tr>`).join('');

  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<title>地址生成记录</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 28px 16px 50px; background: #f6f8fa; color: #1f2328;
         font: 15px/1.6 -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; }
  main { max-width: 1200px; margin: 0 auto; }
  header { display: flex; flex-wrap: wrap; align-items: baseline; gap: 12px; margin-bottom: 14px; }
  h1 { font-size: 1.45rem; margin: 0; }
  .sub { color: #57606a; font-size: 0.88rem; }
  .bar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center;
         background: #fff; border: 1px solid #d0d7de; border-radius: 10px;
         padding: 12px 16px; margin-bottom: 12px; }
  .stat { font-weight: 600; }
  .stat b { color: #0969da; font-size: 1.1rem; }
  .spacer { flex: 1; }
  input[type=search] { padding: 8px 11px; border: 1px solid #d0d7de; border-radius: 7px;
                        font: inherit; min-width: 220px; }
  a.btn, button.btn { display: inline-block; padding: 8px 14px; border-radius: 7px; border: 1px solid #d0d7de;
                      background: #f6f8fa; color: #1f2328; font: inherit; font-weight: 600;
                      text-decoration: none; cursor: pointer; }
  a.btn.primary { background: #238636; border-color: #238636; color: #fff; }
  .wrap { overflow-x: auto; background: #fff; border: 1px solid #d0d7de; border-radius: 10px; }
  table { border-collapse: collapse; width: 100%; min-width: 980px; font-size: 0.88rem; }
  th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #eaeef2; vertical-align: top; }
  th { background: #f6f8fa; color: #57606a; font-weight: 600; white-space: nowrap; position: sticky; top: 0; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f6f8fa; }
  .num { color: #8c959f; width: 46px; }
  .time { white-space: nowrap; font-family: Consolas, "Courier New", monospace; }
  .frag-txt { color: #57606a; white-space: nowrap; }
  code.addr { font-family: Consolas, "Courier New", monospace; word-break: break-all;
              cursor: pointer; color: #0969da; }
  code.addr:hover { text-decoration: underline; }
  .empty { padding: 34px; text-align: center; color: #57606a; }
  .note { margin: 14px 0 0; padding: 14px 16px; background: #fff8c5; border: 1px solid #d4a72c;
          border-radius: 10px; font-size: 0.86rem; color: #4d3800; }
  .note b { color: #7d4e00; }
  ul { margin: 8px 0 0; padding-left: 20px; }
  .toast { position: fixed; right: 20px; bottom: 20px; background: #1f2328; color: #fff;
           padding: 10px 16px; border-radius: 8px; font-size: 0.85rem; opacity: 0;
           transition: opacity .2s; pointer-events: none; }
  .toast.show { opacity: 1; }
</style>
</head>
<body>
<main>
  <header>
    <h1>地址生成记录</h1>
    <span class="sub">每次刷新都实时读取 ${source}，按时间倒序（最新在前）</span>
  </header>

  <div class="bar">
    <span class="stat">共 <b id="count">${total}</b> 条</span>
    <span class="sub">最新：<span id="latest">${escapeHtml(latest)}</span></span>
    ${skipped ? `<span class="sub">跳过 ${skipped} 行损坏数据</span>` : ''}
    <span class="spacer"></span>
    <input type="search" id="q" placeholder="搜索时间 / 片段 / 地址" aria-label="搜索记录">
    <a class="btn primary" href="${path}">刷新</a>
    <a class="btn" href="https://vrbtc.github.io/crypto-address-generator/" rel="noopener noreferrer">去生成地址</a>
    <a class="btn" href="${path}?logout=1">退出查看</a>
  </div>

  <div class="wrap">
    ${total ? `<table>
      <thead><tr>
        <th>#</th><th>生成时间</th><th>原文片段</th>
        <th>ETH 地址</th><th>BTC Legacy</th><th>BTC SegWit</th>
      </tr></thead>
      <tbody id="rows">${body}</tbody>
    </table>` : '<div class="empty">暂无归档记录。生成一次地址后刷新本页即可看到。</div>'}
  </div>

  <div class="note">
    <b>关于「原文」：</b>归档里<b>没有整段原文</b>，只有长原文的前 4 位与后 4 位；短原文连片段都不记。
    原因：本项目里 SHA256(原文) 就是私钥，原文一旦写进任何可打开的网页，等于私钥落盘。
    <ul>
      <li>页面与私有仓库都<b>不含</b>原文、SHA256 私钥、WIF 私钥；私钥只在生成时短暂显示于浏览器。</li>
      <li>归档接口地址公开，来源头可伪造，记录中可能混入他人提交的伪造条目，请勿把本表当作可信账本。</li>
      <li>点击任意地址可复制；本页需要专属链接授权，未授权访问看不到任何记录。</li>
    </ul>
  </div>
</main>
<div class="toast" id="toast">已复制</div>
<script>
(function () {
  var q = document.getElementById('q');
  var rows = Array.prototype.slice.call(document.querySelectorAll('#rows tr'));
  var countEl = document.getElementById('count');
  if (q) q.addEventListener('input', function () {
    var term = q.value.trim().toLowerCase(), shown = 0;
    rows.forEach(function (tr) {
      var hit = !term || tr.textContent.toLowerCase().indexOf(term) >= 0;
      tr.style.display = hit ? '' : 'none';
      if (hit) shown++;
    });
    if (countEl) countEl.textContent = shown;
  });
  var toast = document.getElementById('toast'), timer;
  document.addEventListener('click', function (e) {
    var c = e.target.closest ? e.target.closest('code.addr') : null;
    if (!c) return;
    var text = c.textContent.trim();
    if (!text || text === '—' || !navigator.clipboard) return;
    navigator.clipboard.writeText(text).then(function () {
      toast.classList.add('show');
      clearTimeout(timer);
      timer = setTimeout(function () { toast.classList.remove('show'); }, 1200);
    });
  });
})();
</script>
</body>
</html>`;
}

// 纯函数：未授权访问时的提示页。不泄露仓库名以外的数据，也不给密钥提示。
export function renderLoginHtml(notice = '') {
  const extra = notice
    ? `<p style="color:#a40e26"><b>${escapeHtml(notice)}</b></p>`
    : '';
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<title>需要授权 · 地址生成记录</title>
<style>
  body { margin: 0; padding: 60px 20px; background: #f6f8fa; color: #1f2328;
         font: 16px/1.7 -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; }
  main { max-width: 560px; margin: 0 auto; background: #fff; border: 1px solid #d0d7de;
         border-radius: 12px; padding: 30px 32px; }
  h1 { font-size: 1.3rem; margin: 0 0 10px; }
  p { color: #57606a; margin: 12px 0; }
  a { color: #0969da; }
  code { background: #f6f8fa; padding: 2px 6px; border-radius: 5px; }
</style>
</head>
<body>
<main>
  <h1>这个页面需要专属链接</h1>
  ${extra}
  <p>记录里含有全部生成的钱包地址，不对外公开。请用你保存的专属链接（形如
     <code>https://s.320212.xyz/records?k=…</code>）打开一次，浏览器记住授权后，
     以后直接打开 <a href="/records">https://s.320212.xyz/records</a> 即可。</p>
  <p><a href="/">返回地址生成器</a></p>
</main>
</body>
</html>`;
}

// 纯函数：读取失败时的提示页，避免把 GitHub 错误原文直接吐给浏览器。
export function renderErrorHtml(status) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>读取失败 · 地址生成记录</title>
<style>body{margin:0;padding:60px 20px;background:#f6f8fa;color:#1f2328;
font:16px/1.7 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
main{max-width:560px;margin:0 auto;background:#fff;border:1px solid #d0d7de;
border-radius:12px;padding:30px 32px}h1{font-size:1.3rem;margin:0 0 10px}p{color:#57606a}</style>
</head>
<body><main>
  <h1>暂时读不到记录</h1>
  <p>从私有仓库读取归档文件失败（HTTP ${escapeHtml(status)}）。稍后<a href="/records">刷新重试</a>即可，归档数据本身没有丢失。</p>
</main></body>
</html>`;
}
