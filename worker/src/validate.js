// 归档记录字段白名单。白名单之外的任何字段都拒绝，防止把私钥塞进归档文件。
// mode 是可选字段：'mnemonic' = BIP-39 助记词模式派生的地址，'raw' = 直连哈希模式。
// 无论如何，归档里只允许出现地址，绝不允许出现私钥 / WIF / 助记词。
export const RECORD_FIELDS = Object.freeze([
  'time', 'input_head', 'input_tail', 'eth', 'btc_legacy', 'btc_segwit'
]);
const OPTIONAL_MODE = 'mode';
const RE_MODE = /^(mnemonic|raw)$/;

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const RE_TIME = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/;
const RE_ETH = /^0x[0-9a-fA-F]{40}$/;
const RE_LEGACY = /^[13][1-9A-HJ-NP-Za-km-z]{25,34}$/;
const RE_SEGWIT = new RegExp('^bc1q[' + BECH32_CHARSET + ']{38,58}$');
const RE_CONTROL = /[\u0000-\u001f\u007f]/;
const MAX_RECORD_BYTES = 1024;

function fail(reason) {
  return { ok: false, reason };
}

// 纯函数：校验脱敏归档记录。返回 {ok:true, record} 或 {ok:false, reason}。
export function validateRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return fail('请求体必须是 JSON 对象');
  }

  const keys = Object.keys(value).sort();
  const hasMode = keys.includes(OPTIONAL_MODE);
  // 字段集合只允许两种：6 个基础字段，或 6 个基础字段 + mode。其余一律拒绝。
  const expected = (hasMode ? [...RECORD_FIELDS, OPTIONAL_MODE] : [...RECORD_FIELDS]).sort();
  if (keys.length !== expected.length || keys.some((k, i) => k !== expected[i])) {
    return fail('字段集合不匹配，拒绝任何额外字段');
  }

  const checkedFields = hasMode ? [...RECORD_FIELDS, OPTIONAL_MODE] : [...RECORD_FIELDS];
  for (const field of checkedFields) {
    if (typeof value[field] !== 'string') return fail(field + ' 必须是字符串');
    if (RE_CONTROL.test(value[field])) return fail(field + ' 含控制字符');
  }
  if (hasMode && !RE_MODE.test(value.mode)) {
    return fail('mode 只允许 mnemonic 或 raw');
  }

  if (new TextEncoder().encode(JSON.stringify(value)).length > MAX_RECORD_BYTES) {
    return fail('记录超过 1024 字节');
  }

  if (value.input_head.length > 4 || value.input_tail.length > 4) {
    return fail('原文头尾截取不得超过 4 位');
  }

  const t = RE_TIME.exec(value.time);
  if (!t) return fail('time 格式必须是 YYYY-MM-DD HH:mm:ss');
  const [, y, mo, d, h, mi, s] = t.map(Number);
  const month = Number(mo), day = Number(d);
  if (y < 2000 || y > 9999 || month < 1 || month > 12 || day < 1 || day > 31 ||
      Number(h) > 23 || Number(mi) > 59 || Number(s) > 59) {
    return fail('time 数值超出合法范围');
  }

  if (!RE_ETH.test(value.eth)) return fail('ETH 地址格式不合法');
  if (!RE_LEGACY.test(value.btc_legacy)) return fail('BTC Legacy 地址格式不合法');
  if (!RE_SEGWIT.test(value.btc_segwit)) return fail('BTC SegWit 地址格式不合法');

  return {
    ok: true,
    record: {
      time: value.time,
      input_head: value.input_head,
      input_tail: value.input_tail,
      eth: value.eth,
      btc_legacy: value.btc_legacy,
      btc_segwit: value.btc_segwit,
      // 不传 mode 的旧客户端保持原样，不加多余字段。
      ...(hasMode ? { mode: value.mode } : {})
    }
  };
}

// 纯函数：固定窗口限流。state 来自 KV，nowSec 为 Unix 秒。
// 返回 {allowed, state, retryAfter}，调用方负责把 state 写回 KV。
export function checkRateLimit(state, nowSec, max, windowSec) {
  const valid = state && typeof state.start === 'number' && typeof state.count === 'number';
  if (!valid || !Number.isFinite(state.start) || !Number.isFinite(state.count) ||
      state.count < 0 || !Number.isInteger(state.count) ||
      nowSec - state.start >= windowSec || nowSec < state.start) {
    return { allowed: true, state: { start: nowSec, count: 1 }, retryAfter: 0 };
  }
  if (state.count >= max) {
    return {
      allowed: false,
      state,
      retryAfter: Math.max(1, windowSec - (nowSec - state.start))
    };
  }
  return {
    allowed: true,
    state: { start: state.start, count: state.count + 1 },
    retryAfter: 0
  };
}
