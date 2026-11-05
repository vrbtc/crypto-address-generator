import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(resolve(here, '../../index.html'), 'utf8');

// 与 masking.test.mjs 同样的做法：直接求值线上页面里的标记块，不复制实现。
const fnMatch = /\/\/ SPLIT_FN_START\s*([\s\S]*?)\/\/ SPLIT_FN_END/.exec(html);
assert.ok(fnMatch, 'index.html 必须包含 SPLIT_FN_START / SPLIT_FN_END 标记块');
const splitKey = new Function(fnMatch[1] + '\nreturn splitKey;')();

const ETH_KEY = 'a'.repeat(59) + 'b2345';      // 64 位十六进制私钥的替身
const WIF_KEY = 'L' + 'x'.repeat(46) + 'c6789'; // Base58 WIF 的替身

function blockInnerHtml(containerId) {
  const re = new RegExp('<div class="pk-container" id="' + containerId + '">([\\s\\S]*?)\\n      </div>');
  const m = re.exec(html);
  assert.ok(m, `缺少 ${containerId} 容器`);
  return m[1];
}

// 模拟浏览器「选中整个私钥容器并复制」得到的纯文本：
// 把空元素替换为运行时写入的主段/尾段，再剥离标签，剩下的就是各文本节点的顺序拼接。
function copyWholeBlock(containerId, mainId, tailId, main, tail) {
  let block = blockInnerHtml(containerId);
  const mainTag = new RegExp('<div class="pk-main" id="' + mainId + '"></div>');
  const tailTag = new RegExp('<span class="pk-tail" id="' + tailId + '"></span>');
  assert.ok(mainTag.test(block), `${containerId} 缺少独立主段元素`);
  assert.ok(tailTag.test(block), `${containerId} 缺少独立尾段元素`);
  block = block.replace(mainTag, main).replace(tailTag, tail);
  return block.replace(/<[^>]*>/g, '');
}

test('ETH 64 位私钥：主段 59 位、末 5 位单独存放、拼接可还原', () => {
  const p = splitKey(ETH_KEY);
  assert.equal(p.main.length, 59);
  assert.equal(p.tail, 'b2345');
  assert.equal(p.main + p.tail, ETH_KEY);
});

test('BTC WIF 私钥同样按末 5 位拆分', () => {
  const p = splitKey(WIF_KEY);
  assert.equal(p.tail, 'c6789');
  assert.equal(p.main + p.tail, WIF_KEY);
});

test('长度不足或等于 5 的输入不产生尾段，且不得抛异常', () => {
  for (const v of ['', 'abc', '12345']) {
    const p = splitKey(v);
    assert.equal(p.tail, '', `长度 ${v.length} 不应有尾段`);
    assert.equal(p.main, v);
  }
  assert.equal(splitKey('123456').tail, '23456');
});

test('非字符串输入返回空结果', () => {
  for (const v of [null, undefined, 123, {}, []]) {
    assert.deepEqual(splitKey(v), { main: '', tail: '' });
  }
});

test('ETH 私钥整段复制不会得到完整私钥，且带上可见隔离说明', () => {
  const p = splitKey(ETH_KEY);
  const copied = copyWholeBlock('ethKeyDisplay', 'ethKeyMain', 'ethKeyTail', p.main, p.tail);
  assert.ok(!copied.replace(/\s/g, '').includes(ETH_KEY), '复制文本不得含连续的完整私钥');
  assert.ok(copied.includes('↓ 以下 5 位与主段隔离，请单独抄录 ↓'));
  assert.ok(copied.includes('末 5 位（单独抄录）'));
  assert.ok(copied.includes(p.main));
  assert.ok(copied.includes(p.tail));
});

test('BTC WIF 整段复制同样不会得到完整私钥', () => {
  const p = splitKey(WIF_KEY);
  const copied = copyWholeBlock('btcKeyDisplay', 'btcKeyMain', 'btcKeyTail', p.main, p.tail);
  assert.ok(!copied.replace(/\s/g, '').includes(WIF_KEY), '复制文本不得含连续的完整 WIF');
  assert.ok(copied.includes('↓ 以下 5 位与主段隔离，请单独抄录 ↓'));
});

test('主段与尾段在源码中相隔隔离条，且渲染不再使用 innerHTML 拼接相邻 span', () => {
  for (const [mainId, tailId] of [['ethKeyMain', 'ethKeyTail'], ['btcKeyMain', 'btcKeyTail']]) {
    const iMain = html.indexOf(`id="${mainId}"`);
    const iTail = html.indexOf(`id="${tailId}"`);
    assert.ok(iMain >= 0 && iTail > iMain, `${mainId} 必须在 ${tailId} 之前`);
    assert.ok(html.slice(iMain, iTail).includes('class="pk-gap"'), '两段之间必须有隔离说明条');
  }
  assert.ok(!/showSplitKey[\s\S]{0,300}innerHTML/.test(html), '不得再用 innerHTML 拼私钥');
  assert.ok(/document\.getElementById\(mainId\)\.textContent/.test(html));
  assert.ok(/document\.getElementById\(tailId\)\.textContent/.test(html));
});

test('复制按钮仍只复制主段元素，不会连尾段一起带走', () => {
  assert.ok(html.includes("copyText('ethKeyMain')"));
  assert.ok(html.includes("copyText('btcKeyMain')"));
  assert.ok(!html.includes("copyText('ethKeyDisplay')"), '不得复制整个容器');
  assert.ok(!html.includes("copyText('btcKeyDisplay')"), '不得复制整个容器');
});
