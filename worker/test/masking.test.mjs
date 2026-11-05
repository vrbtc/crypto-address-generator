import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// 归档脱敏规则定义在单文件页面 index.html 中；用标记块提取后求值，
// 保证测试跑的就是线上页面实际执行的那段代码，而不是复制品。
const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(resolve(here, '../../index.html'), 'utf8');
const match = /\/\/ MASKING_FN_START\s*([\s\S]*?)\/\/ MASKING_FN_END/.exec(html);
assert.ok(match, 'index.html 必须包含 MASKING_FN_START / MASKING_FN_END 标记块');
const maskInput = new Function(match[1] + '\nreturn maskInput;')();

test('8 位日期原文：头尾拼回等于完整原文，必须全部留空', () => {
  // 修复前 head='2026'、tail='1105'，拼起来就是 20261105。
  assert.deepEqual(maskInput('20261105'), { head: '', tail: '' });
});

test('长度小于 12 的输入一律不记录任何片段', () => {
  for (const n of [0, 1, 4, 7, 8, 9, 11]) {
    const got = maskInput('x'.repeat(n));
    assert.deepEqual(got, { head: '', tail: '' }, `长度 ${n} 应留空`);
  }
});

test('长度等于 12 的边界值开始记录头尾各 4 位', () => {
  assert.deepEqual(maskInput('abcdefghijkl'), { head: 'abcd', tail: 'ijkl' });
});

test('长度大于 12 时取前 4 与后 4 位', () => {
  assert.deepEqual(maskInput('ABCDEFGHIJKLMNOP'), { head: 'ABCD', tail: 'MNOP' });
});

test('非字符串输入不抛异常且返回空片段', () => {
  for (const v of [null, undefined, 123, {}, []]) {
    assert.deepEqual(maskInput(v), { head: '', tail: '' });
  }
});

test('片段长度始终不超过 4 个 UTF-16 码元，满足 Worker 字段校验', () => {
  // emoji 是代理对，UTF-16 切片可能切断；此处断言不会产生超过 4 码元的片段，
  // 否则 Worker 会以「原文头尾截取不得超过 4 位」返回 400。
  const got = maskInput('😀😀😀😀😀😀😀😀😀😀😀😀');
  assert.ok(got.head.length <= 4, `head.length=${got.head.length}`);
  assert.ok(got.tail.length <= 4, `tail.length=${got.tail.length}`);
});

test('纯函数：同一输入多次调用结果一致', () => {
  const raw = 'a-long-enough-passphrase';
  assert.deepEqual(maskInput(raw), maskInput(raw));
});
