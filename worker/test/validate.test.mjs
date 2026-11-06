import test from 'node:test';
import assert from 'node:assert/strict';
import { validateRecord, checkRateLimit } from '../src/validate.js';
import { bytesToBase64, base64ToBytes, encodeUtf8, decodeUtf8 } from '../src/encoding.js';

// 交接文档第五节的回归基准记录（输入 20261105）
const GOOD = {
  time: '2026-11-05 02:24:05',
  input_head: '2026',
  input_tail: '1105',
  eth: '0xb1a2adc8139fdc39db95ab66920463c0a47229f7',
  btc_legacy: '1HyQAhSW7HrrE2VV9f3uBD9HTyajeihPZ1',
  btc_segwit: 'bc1qhgk22w8sylxl7c40awxpyhypmtk0erwtjwnfph'
};

const clone = o => JSON.parse(JSON.stringify(o));

test('合法基准记录通过，且只保留白名单字段', () => {
  const r = validateRecord(GOOD);
  assert.equal(r.ok, true);
  assert.deepEqual(r.record, GOOD);
  assert.ok(!('mode' in r.record), '不传 mode 时输出记录不得新增字段');
});

test('mode 字段：mnemonic / raw 允许并保留，其他值拒绝', () => {
  const mn = clone(GOOD); mn.mode = 'mnemonic';
  const r1 = validateRecord(mn);
  assert.equal(r1.ok, true);
  assert.equal(r1.record.mode, 'mnemonic');
  assert.equal(Object.keys(r1.record).length, 7);

  const raw = clone(GOOD); raw.mode = 'raw';
  const r2 = validateRecord(raw);
  assert.equal(r2.ok, true);
  assert.equal(r2.record.mode, 'raw');

  for (const bad of ['seed', 'MNEMONIC', 'mnemonic ', 'privkey', '']) {
    const b = clone(GOOD); b.mode = bad;
    const r = validateRecord(b);
    assert.equal(r.ok, false, `mode=${bad} 必须被拒绝`);
    if (bad) assert.match(r.reason, /mode/);
  }
  const num = clone(GOOD); num.mode = 123;
  assert.equal(validateRecord(num).ok, false);
});

test('多余字段一律拒绝，尤其私钥类字段', () => {
  for (const extra of ['private_key', 'wif', 'secret', 'raw_input', 'token']) {
    const bad = clone(GOOD);
    bad[extra] = 'super-secret';
    const r = validateRecord(bad);
    assert.equal(r.ok, false, `字段 ${extra} 必须被拒绝`);
    assert.match(r.reason, /字段集合/);
  }
});

test('缺字段 / 字段类型错误一律拒绝', () => {
  const missing = clone(GOOD);
  delete missing.input_tail;
  assert.equal(validateRecord(missing).ok, false);

  const wrongType = clone(GOOD);
  wrongType.eth = 123;
  assert.equal(validateRecord(wrongType).ok, false);
});

test('非对象请求体一律拒绝', () => {
  for (const v of [null, undefined, [], 'text', 42, true]) {
    assert.equal(validateRecord(v).ok, false);
  }
});

test('地址格式错误一律拒绝', () => {
  const cases = [
    ['eth', '0x1234'],
    ['eth', '0x' + 'z'.repeat(40)],
    ['btc_legacy', '0HyQAhSW7HrrE2VV9f3uBD9HTyajeihPZ1'],
    ['btc_legacy', '1HyQAhSW7HrrE2VV9f3uBD9HTyajeihPZl'],
    ['btc_segwit', 'bc1p' + 'q'.repeat(38)],
    ['btc_segwit', 'bc1q' + 'b'.repeat(38)],
    ['btc_segwit', 'bc1qshort']
  ];
  for (const [field, value] of cases) {
    const bad = clone(GOOD);
    bad[field] = value;
    const r = validateRecord(bad);
    assert.equal(r.ok, false, `${field}=${value} 必须被拒绝`);
  }
});

test('头尾截取超过 4 位拒绝，控制字符拒绝', () => {
  const longHead = clone(GOOD);
  longHead.input_head = '20261';
  assert.equal(validateRecord(longHead).ok, false);

  const ctrl = clone(GOOD);
  ctrl.input_tail = '11\n5';
  assert.equal(validateRecord(ctrl).ok, false);
});

test('时间格式与数值范围校验', () => {
  for (const t of ['2026-13-05 02:24:05', '2026-11-32 02:24:05',
                   '2026-11-05 25:24:05', '2026-11-05 02:60:05',
                   '2026/11/05 02:24:05', 'not-a-time']) {
    const bad = clone(GOOD);
    bad.time = t;
    assert.equal(validateRecord(bad).ok, false, `${t} 必须被拒绝`);
  }
});

test('限流：窗口内累计、超限拒绝、窗口过期重置', () => {
  const now = 1730000000;
  const first = checkRateLimit(null, now, 3, 60);
  assert.equal(first.allowed, true);
  assert.deepEqual(first.state, { start: now, count: 1 });

  const second = checkRateLimit(first.state, now + 1, 3, 60);
  assert.equal(second.allowed, true);
  assert.equal(second.state.count, 2);

  const third = checkRateLimit(second.state, now + 2, 3, 60);
  assert.equal(third.allowed, true);
  assert.equal(third.state.count, 3);

  const blocked = checkRateLimit(third.state, now + 3, 3, 60);
  assert.equal(blocked.allowed, false);
  assert.ok(blocked.retryAfter > 0);

  const reset = checkRateLimit(third.state, now + 60, 3, 60);
  assert.equal(reset.allowed, true);
  assert.deepEqual(reset.state, { start: now + 60, count: 1 });
});

test('限流：损坏状态与时钟回退自愈', () => {
  const now = 1730000000;
  for (const bad of ['garbage', { start: NaN, count: 1 }, { start: now, count: -5 },
                     { start: 'x', count: 1 }]) {
    const r = checkRateLimit(bad, now, 3, 60);
    assert.equal(r.allowed, true);
    assert.deepEqual(r.state, { start: now, count: 1 });
  }
  const back = checkRateLimit({ start: now + 10, count: 1 }, now, 3, 60);
  assert.equal(back.allowed, true);
  assert.equal(back.state.start, now);
});

test('UTF-8 与 Base64 往返：中文、emoji、含换行 base64', () => {
  for (const text of ['中文测试 2026', '🔑 emoji', 'line1\nline2\n', '']) {
    assert.equal(decodeUtf8(base64ToBytes(bytesToBase64(encodeUtf8(text)))), text);
  }
  const wrapped = bytesToBase64(encodeUtf8('归档')).replace(/(.{4})/g, '$1\n');
  assert.equal(decodeUtf8(base64ToBytes(wrapped)), '归档');
});

test('大文本分块编码不触发参数上限', () => {
  const text = 'x'.repeat(100000);
  const b64 = bytesToBase64(encodeUtf8(text));
  assert.equal(decodeUtf8(base64ToBytes(b64)), text);
});
