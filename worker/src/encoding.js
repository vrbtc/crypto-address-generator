// UTF-8 <-> Base64 转换。分块处理，避免大文件触发 String.fromCharCode 参数上限。
export function bytesToBase64(bytes) {
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

export function base64ToBytes(base64) {
  const clean = base64.replace(/\s/g, '');
  const binary = atob(clean);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function encodeUtf8(text) {
  return new TextEncoder().encode(text);
}

export function decodeUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}
