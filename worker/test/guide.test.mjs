import test from 'node:test';
import assert from 'node:assert/strict';
import { PAGE_URL, GUIDE_HTML } from '../src/guide.js';

test('页面入口指向 GitHub Pages 生成器，且说明页含该链接', () => {
  assert.equal(PAGE_URL, 'https://vrbtc.github.io/crypto-address-generator/');
  assert.ok(GUIDE_HTML.includes(PAGE_URL));
});

test('说明页明确解释 GET 与 POST 的区别', () => {
  assert.ok(GUIDE_HTML.includes('POST'));
  assert.ok(GUIDE_HTML.includes('GET'));
  assert.ok(GUIDE_HTML.includes('只接受 POST'));
});

test('说明页给出根路径跳转与健康检查入口', () => {
  assert.ok(GUIDE_HTML.includes('https://s.320212.xyz/'));
  assert.ok(GUIDE_HTML.includes('/health'));
});

test('说明页给出可直接打开的记录页入口', () => {
  assert.ok(GUIDE_HTML.includes('href="/records"'));
  assert.ok(GUIDE_HTML.includes('https://s.320212.xyz/records'));
  assert.ok(GUIDE_HTML.includes('无需调用接口'));
});

test('说明页给出可直接复制的 curl POST 示例，且不含会被校验拒绝的占位符', () => {
  assert.ok(GUIDE_HTML.includes('curl -X POST https://s.320212.xyz/archive'));
  assert.ok(GUIDE_HTML.includes('Content-Type: application/json'));
  assert.ok(GUIDE_HTML.includes('0xb1a2adc8139fdc39db95ab66920463c0a47229f7'));
  assert.ok(GUIDE_HTML.includes('1HyQAhSW7HrrE2VV9f3uBD9HTyajeihPZ1'));
  assert.ok(!GUIDE_HTML.includes('"eth":"0x..."'), '示例不得留地址占位符');
});

test('说明页声明不记录原文、SHA256 私钥与 WIF', () => {
  for (const word of ['原文', 'SHA256', 'WIF']) {
    assert.ok(GUIDE_HTML.includes(word), `缺少 ${word}`);
  }
});

test('说明页是完整 HTML 文档且不含模板残留', () => {
  assert.ok(GUIDE_HTML.startsWith('<!doctype html>'));
  assert.ok(GUIDE_HTML.trimEnd().endsWith('</html>'));
  assert.ok(!GUIDE_HTML.includes('${'), '模板变量必须已全部求值');
});
