import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  VIEWER_COOKIE, RECORDS_PATH, VIEWER_TOKEN_SUFFIX,
  viewerCookie, escapeHtml, safeEqual, parseCookie, parseJsonl, fragmentLabel,
  renderRecordsHtml, renderLoginHtml, renderErrorHtml
} from '../src/records.js';

const row = (over = {}) => ({
  time: '2026-11-05 10:01:39',
  input_head: '2026', input_tail: '1105',
  eth: '0xb1a2adc8139fdc39db95ab66920463c0a47229f7',
  btc_legacy: '1HyQAhSW7HrrE2VV9f3uBD9HTyajeihPZ1',
  btc_segwit: 'bc1qhgk22w8sylxl7c40awxpyhypmtk0erwtjwnfph',
  ...over
});

test('HTML 转义覆盖五种危险字符，空值不抛错', () => {
  assert.equal(escapeHtml(`&<>"'`), '&amp;&lt;&gt;&quot;&#39;');
  assert.equal(escapeHtml(undefined), '');
  assert.equal(escapeHtml(null), '');
  assert.equal(escapeHtml(0), '0');
});

test('常量时间比较：相等通过，长度不同/内容不同/空值一律拒绝', () => {
  assert.equal(safeEqual('abc123', 'abc123'), true);
  assert.equal(safeEqual('abc123', 'abc124'), false);
  assert.equal(safeEqual('abc', 'abcd'), false);
  assert.equal(safeEqual('', ''), true);
  assert.equal(safeEqual(null, undefined), true);
  assert.equal(safeEqual('abc', ''), false);
  assert.equal(VIEWER_COOKIE, 'wallet_view');
  assert.equal(RECORDS_PATH, '/records');
  assert.ok(VIEWER_TOKEN_SUFFIX.includes('viewer'));
});

test('查看凭据 Cookie：HttpOnly + Secure + Lax，且限定在 /records 路径', () => {
  const c = viewerCookie('deadbeef', 3600);
  assert.ok(c.startsWith('wallet_view=deadbeef;'));
  for (const attr of ['HttpOnly', 'Secure', 'SameSite=Lax', 'Path=/records', 'Max-Age=3600']) {
    assert.ok(c.includes(attr), `缺少 ${attr}`);
  }
  assert.ok(!c.includes('SameSite=Strict'), 'Strict 会让跨站跳转丢失 Cookie');
  assert.ok(viewerCookie('', 0).includes('Max-Age=0'), '退出登录必须能清除 Cookie');
});

test('Cookie 解析：正常值、多段、缺失、URL 编码与坏编码', () => {
  assert.equal(parseCookie('a=1; wallet_view=deadbeef; b=2', 'wallet_view'), 'deadbeef');
  assert.equal(parseCookie('wallet_view=a%20b', 'wallet_view'), 'a b');
  assert.equal(parseCookie('a=1', 'wallet_view'), null);
  assert.equal(parseCookie(null, 'wallet_view'), null);
  assert.equal(parseCookie('wallet_view=%E0%A4%A', 'wallet_view'), null);
});

test('parseJsonl：正常记录、空行、损坏行、非对象行分别处理', () => {
  const text = [
    JSON.stringify(row()),
    '',
    '{not json',
    '[1,2,3]',
    JSON.stringify(row({ time: '2026-11-05 10:02:00' })),
    JSON.stringify(null)
  ].join('\n');
  const out = parseJsonl(text);
  assert.equal(out.records.length, 2);
  assert.equal(out.skipped, 3);
  assert.equal(out.records[0].eth, row().eth);
  assert.equal(out.records[1].time, '2026-11-05 10:02:00');
});

test('parseJsonl：字段类型异常与超长值不会破坏页面', () => {
  const bad = row({ eth: { nested: 'x' }, input_head: 'A'.repeat(500) });
  const out = parseJsonl(JSON.stringify(bad));
  assert.equal(out.records.length, 1);
  assert.ok(out.records[0].eth.includes('nested'));
  assert.equal(out.records[0].input_head.length, 201); // 200 字符 + 省略号
  assert.ok(out.records[0].input_head.endsWith('…'));
  const empty = parseJsonl('');
  assert.deepEqual(empty, { records: [], skipped: 0 });
});

test('原文片段：短原文留空，长原文只显示头尾，绝不拼回完整原文', () => {
  assert.match(fragmentLabel('', ''), /短原文/);
  assert.match(fragmentLabel('2026', '1105'), /前4位 2026/);
  assert.match(fragmentLabel('2026', '1105'), /后4位 1105/);
  assert.equal(fragmentLabel('', '1105'), '后4位 1105');
});

test('parseJsonl：mode 字段保留用于展示，异常 mode 不展示', () => {
  const out = parseJsonl(JSON.stringify(row({ mode: 'mnemonic' })));
  assert.equal(out.records[0].mode, 'mnemonic');

  const noMode = parseJsonl(JSON.stringify(row()));
  assert.ok(!('mode' in noMode.records[0]));

  const html = renderRecordsHtml([row({ mode: 'mnemonic' })]);
  assert.ok(html.includes('mode-badge'), '缺少徽标样式');
  assert.ok(html.includes('助记词'), '缺少徽标文字');
  assert.ok(html.includes('2026-11-05 10:01:39'), '时间仍需完整展示');
  const plain = renderRecordsHtml([row()]);
  assert.ok(!plain.includes('mode-badge">'), '无 mode 记录不得渲染徽标');

  const fake = renderRecordsHtml([row({ mode: '<b>x</b>' })]);
  assert.ok(!fake.includes('mode-badge">助记词'), '未知 mode 不得渲染成助记词徽标');
  assert.ok(!fake.includes('<b>x</b>') && !fake.includes('&lt;b&gt;x'), '未知 mode 值不得出现在页面');
});

test('记录页渲染：六个字段全部可见，条数与最新时间正确', () => {
  const html = renderRecordsHtml([row(), row({ time: '2026-11-05 09:00:00' })], { skipped: 2 });
  for (const val of ['2026-11-05 10:01:39', '2026-11-05 09:00:00',
    row().eth, row().btc_legacy, row().btc_segwit]) {
    assert.ok(html.includes(val), `缺少 ${val}`);
  }
  assert.ok(html.includes('id="count">2<'));
  assert.ok(html.includes('跳过 2 行损坏数据'));
  assert.ok(html.includes('最新：<span id="latest">2026-11-05 10:01:39'));
});

test('记录页渲染：伪造记录里的脚本注入被转义，不会成为可执行标签', () => {
  const evil = '<script>alert(1)</script>';
  const html = renderRecordsHtml([row({ eth: evil, time: '2026-11-05 10:00:00' })]);
  assert.ok(!html.includes(evil), '注入脚本不得原样出现');
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(!html.includes('${'), '模板变量必须全部求值');
});

test('记录页渲染：空记录有提示；安全声明明确不含原文与私钥', () => {
  const empty = renderRecordsHtml([]);
  assert.ok(empty.includes('暂无归档记录'));
  assert.ok(empty.includes('id="count">0<'));
  for (const word of ['原文', 'SHA256', 'WIF', '私钥', '伪造']) {
    assert.ok(empty.includes(word), `缺少声明 ${word}`);
  }
  assert.ok(empty.startsWith('<!doctype html>'));
  assert.ok(empty.trimEnd().endsWith('</html>'));
});

test('记录页渲染：数据来源可配置且被转义，含搜索、刷新与退出入口', () => {
  const html = renderRecordsHtml([row()], { source: 'vrbtc/wallet-record / records.jsonl' });
  assert.ok(html.includes('vrbtc/wallet-record / records.jsonl'));
  assert.ok(html.includes('id="q"'));
  assert.ok(html.includes('/records?logout=1'));
  assert.ok(html.includes('去生成地址'));
});

test('生成器页面不出现记录页入口（入口保持隐藏）', () => {
  const html = fs.readFileSync(new URL('../../index.html', import.meta.url), 'utf8');
  assert.ok(!html.includes('s.320212.xyz/records'), '生成器页面不得出现记录页链接');
  assert.ok(!html.includes('查看全部生成记录'), '生成器页面不得出现记录页入口文字');
});

test('未授权页与错误页：完整 HTML、不泄露数据、提示文案可转义', () => {
  const login = renderLoginHtml('服务端尚未配置查看密钥');
  assert.ok(login.startsWith('<!doctype html>'));
  assert.ok(login.includes('需要专属链接'));
  assert.ok(login.includes('服务端尚未配置查看密钥'));
  assert.ok(login.includes('/records?k='));
  assert.ok(!login.includes('${'));
  const err = renderErrorHtml('404');
  assert.ok(err.includes('暂时读不到记录'));
  assert.ok(err.includes('HTTP 404'));
  assert.ok(!err.includes('${'));
  assert.ok(renderLoginHtml('<img src=x>').includes('&lt;img src=x&gt;'));
});
