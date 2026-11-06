import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(resolve(here, '../../index.html'), 'utf8');

// 与 masking/keysplit 测试同一做法：直接求值线上页面里的标记块，测试跑的就是要上线的代码。
function extract(startMark, endMark) {
  const re = new RegExp('// ' + startMark + '\\s*([\\s\\S]*?)// ' + endMark);
  const m = re.exec(html);
  assert.ok(m, `index.html 必须包含 ${startMark} / ${endMark} 标记块`);
  return m[1];
}

// maskMnemonic：纯函数提取
const maskMnemonic = new Function(
  extract('MNEMONIC_MASK_FN_START', 'MNEMONIC_MASK_FN_END') + '\nreturn maskMnemonic;')();

// deriveMnemonicCore：依赖 bech32 段（segwitAddrEncode）与 ethers，两者一并提供
const bech32Code = extract('BECH32_BLOCK_START', 'BECH32_BLOCK_END');
const deriveCode = extract('MNEMONIC_DERIVE_FN_START', 'MNEMONIC_DERIVE_FN_END');
const deriveMnemonicCore = new Function(
  bech32Code + '\n' + deriveCode + '\nreturn deriveMnemonicCore;')();

// —— BIP-39 / BIP-32 官方测试向量（Trezor 文档 + 社区公认的 "all abandon" 钱包） ——
// 128 位全零熵 → 12 个 abandon + about（BIP-39 英文词表标准向量）
const ZERO_ENTROPY = new Uint8Array(16);
const ABANDON_PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
// 上述助记词在口令为空时的标准派生地址（与 Ian Coleman / MetaMask 一致的公认向量）
const VEC_ETH_ADDR = '0x9858EfFD232B4033E47d90003D41EC34EcaEda94';
const VEC_LEGACY = '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA';
const VEC_SEGWIT = 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu';

test('maskMnemonic：12 词返回前 8 词与隐藏数 4', () => {
  const words = ABANDON_PHRASE.split(' ');
  const r = maskMnemonic(words);
  assert.equal(r.shown.length, 8);
  assert.equal(r.hiddenCount, 4);
  assert.deepEqual(r.shown, words.slice(0, 8));
  assert.ok(!r.shown.includes(words[11]), '最后一个词绝不能出现在可复制部分');
});

test('maskMnemonic：不足 5 词全隐藏，异常输入不抛错', () => {
  assert.deepEqual(maskMnemonic(['a', 'b', 'c', 'd']), { shown: [], hiddenCount: 4 });
  assert.deepEqual(maskMnemonic(['a', 'b', 'c', 'd', 'e']),
    { shown: ['a'], hiddenCount: 4 });
  for (const v of [null, undefined, 'text', 123, {}]) {
    assert.deepEqual(maskMnemonic(v), { shown: [], hiddenCount: 0 });
  }
});

test('deriveMnemonicCore：全零熵产出标准 BIP-39 12 词（官方向量）', async () => {
  const mw = await deriveMnemonicCore(ZERO_ENTROPY, ethers);
  assert.equal(mw.words.length, 12);
  assert.equal(mw.phrase, ABANDON_PHRASE);
});

test('deriveMnemonicCore：助记词可逆回熵，熵切片正确', async () => {
  const input = createHash('sha256').update('20261105').digest().subarray(0, 16);
  const mw = await deriveMnemonicCore(new Uint8Array(input), ethers);
  const back = ethers.utils.mnemonicToEntropy(mw.phrase);
  assert.deepEqual(ethers.utils.arrayify(back), new Uint8Array(input));
  // 同一原文熵的确定性
  const again = await deriveMnemonicCore(new Uint8Array(input), ethers);
  assert.equal(again.phrase, mw.phrase);
  assert.equal(again.ethAddress, mw.ethAddress);
});

test('deriveMnemonicCore：标准 "all abandon" 钱包多链地址与公认向量一致', async () => {
  const mw = await deriveMnemonicCore(ZERO_ENTROPY, ethers);
  assert.equal(mw.ethAddress, VEC_ETH_ADDR);
  // 私钥正确性由 secp256k1 保证：从返回私钥重算地址必须等于向量地址
  assert.equal(ethers.utils.computeAddress('0x' + mw.ethPrivateKey), VEC_ETH_ADDR);
  // m/44' 派生私钥与 WIF 必须同源
  const node44 = ethers.utils.HDNode.fromSeed(ethers.utils.mnemonicToSeed(mw.phrase))
    .derivePath("m/44'/0'/0'/0/0");
  assert.equal(mw.btcWif.startsWith('L') || mw.btcWif.startsWith('K'), true, '压缩 WIF 以 L/K 开头');
  assert.equal(node44.privateKey.replace(/^0x/, '').length, 64);
  assert.equal(mw.btcLegacy, VEC_LEGACY);
  assert.equal(mw.btcSegwit, VEC_SEGWIT);
});

test('deriveMnemonicCore：WIF 可由私钥复算，且与派生私钥一致', async () => {
  const mw = await deriveMnemonicCore(ZERO_ENTROPY, ethers);
  const node44 = ethers.utils.HDNode.fromSeed(ethers.utils.mnemonicToSeed(mw.phrase))
    .derivePath("m/44'/0'/0'/0/0");
  const wifPayload = '80' + node44.privateKey.replace(/^0x/, '') + '01';
  const wifChecksum = ethers.utils.sha256(ethers.utils.sha256('0x' + wifPayload)).substring(2, 10);
  assert.equal(mw.btcWif, ethers.utils.base58.encode('0x' + wifPayload + wifChecksum));
  // WIF 逆解析回私钥（Base58 解码 → 0x80 前缀 + 32 字节私钥 + 0x01 压缩标记 + 4 字节校验）
  const decoded = ethers.utils.base58.decode(mw.btcWif);
  const hex = ethers.utils.hexlify(decoded).substring(2);
  assert.equal(hex.length, 38 * 2, 'WIF 解码应为 38 字节');
  assert.ok(hex.startsWith('80'));
  assert.ok(hex.slice(66, 68) === '01', '压缩标记 0x01 必须在私钥之后');
  assert.equal(hex.substring(2, 66), node44.privateKey.replace(/^0x/, ''));
});

test('页面结构：助记词板块置顶、直连板块下移，派生路径为标准值', () => {
  const iGrid = html.indexOf('id="mnemonicGrid"');
  const iDirect = html.indexOf('id="ethKeyDisplay"');
  assert.ok(iGrid >= 0 && iDirect > iGrid, '助记词板块必须排在直连哈希板块之前');
  for (const path of ["m/44'/60'/0'/0/0", "m/44'/0'/0'/0/0", "m/84'/0'/0'/0/0"]) {
    assert.ok(html.includes(path), `缺少标准派生路径 ${path}`);
  }
  assert.ok(html.includes('entropyToMnemonic'), '必须走标准 BIP-39 词表转换');
  assert.ok(html.includes('slice(0, 16)'), '熵必须截取 SHA-256 前 16 字节');
});

test('页面行为：第 9-12 词默认不写 DOM、不进剪贴板，全部复制仅在揭示后开放', () => {
  // 初始状态为未揭示，且每次生成后强制回到未揭示
  assert.ok(html.includes('let wordsRevealed = false;'));
  assert.ok(html.includes('wordsRevealed = false; // 每次生成回到默认保护态'));
  // 未揭示时占位符而非真实单词
  assert.ok(html.includes("'🔒 隐藏'"), '被掩码的词必须渲染占位符');
  // 复制全部按钮默认隐藏，揭示后才显示
  assert.ok(/id="btnCopyAll"[^>]*style="display:none"/.test(html),
    '复制全部 12 词按钮默认必须隐藏');
  assert.ok(html.includes("style.display = wordsRevealed ? '' : 'none'"));
  // 复制前 8 词经由 maskMnemonic，不可能带出后 4 词
  assert.ok(html.includes('const { shown } = maskMnemonic(currentWords);'));
  // 复制全部入口有揭示态守卫
  assert.ok(html.includes('if (!currentWords || !wordsRevealed) return;'));
});

test('页面行为：归档只带地址与 mode，绝不含助记词/私钥字段', () => {
  assert.ok(html.includes("'mnemonic'"), '归档必须带 mode=mnemonic');
  assert.ok(html.includes('/字段集合/'), '必须保留对旧版 Worker 的 mode 降级重试');
  // 归档记录字段集合固定，不允许 phrase/words/私钥混入
  const archiveBlock = /async function archive\([\s\S]*?const record = mode \? \{ \.\.\.base, mode: mode \} : base;/.test(html);
  assert.ok(archiveBlock, '归档 record 只能来自 6 字段 base + mode');
  assert.ok(!/record\.(phrase|words|privateKey|btcWif|ethPrivateKey)/.test(html));
});
