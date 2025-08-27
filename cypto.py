# cypto_streamlit.py
import hashlib
import ecdsa
import base58
from eth_utils import keccak
import bech32
import streamlit as st

# ---------- 地址生成逻辑 ----------

def sha256_hash(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def private_key_to_wif(private_key_hex: str) -> str:
    private_key_bytes = bytes.fromhex(private_key_hex)
    extended_key = b"\x80" + private_key_bytes + b"\x01"
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    return base58.b58encode(extended_key + checksum).decode()

def private_key_to_compressed_public_key(private_key_bytes):
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    return prefix + x.to_bytes(32, 'big')

def private_key_to_uncompressed_public_key(private_key_bytes):
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")

def public_key_to_btc_address(public_key_bytes):
    sha256_pk = hashlib.sha256(public_key_bytes).digest()
    ripemd160_pk = hashlib.new("ripemd160", sha256_pk).digest()
    prefixed_hash = b"\x00" + ripemd160_pk
    checksum = hashlib.sha256(hashlib.sha256(prefixed_hash).digest()).digest()[:4]
    return base58.b58encode(prefixed_hash + checksum).decode()

def public_key_to_segwit_address(public_key_bytes):
    sha256_pk = hashlib.sha256(public_key_bytes).digest()
    ripemd160_pk = hashlib.new("ripemd160", sha256_pk).digest()
    return bech32.encode("bc", 0, ripemd160_pk)

def public_key_to_eth_address(uncompressed_public_key):
    pubkey_bytes = uncompressed_public_key[1:]
    address = keccak(pubkey_bytes)[-20:]
    return "0x" + address.hex()

# ---------- Streamlit 页面 ----------

st.set_page_config(page_title="多链地址生成器", layout="wide")
st.title("🔑 多链地址生成器")
st.write("输入任意文本生成 ETH 和 BTC 多链地址。")

user_input = st.text_input("请输入任意文本（密码、短语等）：")

if user_input:
    sha256_result = sha256_hash(user_input)
    private_key_bytes = bytes.fromhex(sha256_result)

    # ETH
    st.subheader("Ethereum (ETH)")
    # 私钥前后分段显示
    st.markdown(
        f"""**ETH 私钥:** <span style='display:inline-block'>{sha256_result[:-5]}</span>
        <span style='color:red; display:inline-block'>{sha256_result[-5:]}</span>""",
        unsafe_allow_html=True,
    )
    st.text_input("ETH 私钥 (可复制)", sha256_result, key="eth_priv", help="手动复制前端输入框的内容")

    uncompressed_pubkey = private_key_to_uncompressed_public_key(private_key_bytes)
    eth_address = public_key_to_eth_address(uncompressed_pubkey)
    st.text_input("ETH 地址", eth_address, key="eth_addr")

    # BTC
    st.subheader("Bitcoin (BTC)")
    wif = private_key_to_wif(sha256_result)
    st.markdown(
        f"""**BTC 私钥 (WIF):** <span style='display:inline-block'>{wif[:-5]}</span>
        <span style='color:red; display:inline-block'>{wif[-5:]}</span>""",
        unsafe_allow_html=True,
    )
    st.text_input("BTC 私钥 (WIF, 可复制)", wif, key="btc_priv", help="手动复制前端输入框的内容")

    compressed_pubkey = private_key_to_compressed_public_key(private_key_bytes)
    btc_address = public_key_to_btc_address(compressed_pubkey)
    segwit_address = public_key_to_segwit_address(compressed_pubkey)
    st.text_input("BTC 传统地址", btc_address, key="btc_addr")
    st.text_input("BTC SegWit 地址", segwit_address, key="btc_segwit")
