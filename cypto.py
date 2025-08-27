import hashlib
import ecdsa
import base58
from eth_utils import keccak
import bech32
import streamlit as st
import pyperclip

st.set_page_config(page_title="多链地址生成器", layout="centered")

# ---------- 地址生成逻辑 ----------
def sha256_hash(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def private_key_to_wif(private_key_hex: str) -> str:
    private_key_bytes = bytes.fromhex(private_key_hex)
    extended_key = b"\x80" + private_key_bytes + b"\x01"
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    final_key = extended_key + checksum
    return base58.b58encode(final_key).decode()

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

def public_key_to_eth_address(uncompressed_public_key):
    pubkey_bytes = uncompressed_public_key[1:]
    address = keccak(pubkey_bytes)[-20:]
    return "0x" + address.hex()

def public_key_to_btc_address(public_key_bytes):
    sha256_pk = hashlib.sha256(public_key_bytes).digest()
    ripemd160_pk = hashlib.new("ripemd160", sha256_pk).digest()
    prefixed_hash = b"\x00" + ripemd160_pk
    checksum = hashlib.sha256(hashlib.sha256(prefixed_hash).digest()).digest()[:4]
    binary_address = prefixed_hash + checksum
    return base58.b58encode(binary_address).decode()

def public_key_to_segwit_address(public_key_bytes):
    sha256_pk = hashlib.sha256(public_key_bytes).digest()
    ripemd160_pk = hashlib.new("ripemd160", sha256_pk).digest()
    return bech32.encode("bc", 0, ripemd160_pk)

# ---------- Streamlit 页面 ----------
st.title("🔑 多链地址生成器")
st.write("输入任意文本生成 ETH/BTC 多链地址及私钥")

user_input = st.text_input("请输入任意文本（密码、短语等）", "")

if st.button("生成地址") and user_input:
    sha256_result = sha256_hash(user_input)
    private_key_bytes = bytes.fromhex(sha256_result)

    # ------------------ ETH ------------------
    st.subheader("Ethereum (ETH)")
    uncompressed_pubkey = private_key_to_uncompressed_public_key(private_key_bytes)
    eth_address = public_key_to_eth_address(uncompressed_pubkey)

    displayed_eth_key = sha256_result[:-5] + f"<span style='color:red'>{sha256_result[-5:]}</span>"
    st.markdown(f"**ETH 私钥:** {displayed_eth_key}", unsafe_allow_html=True)
    if st.button("复制 ETH 私钥（不含后5位）"):
        pyperclip.copy(sha256_result[:-5])
        st.success("ETH 私钥已复制（最后5位未复制）")

    st.text_input("ETH 地址", eth_address, key="eth_address_input")
    if st.button("复制 ETH 地址"):
        pyperclip.copy(eth_address)
        st.success("ETH 地址已复制")

    # ------------------ BTC ------------------
    st.subheader("Bitcoin (BTC)")
    wif = private_key_to_wif(sha256_result)
    compressed_pubkey = private_key_to_compressed_public_key(private_key_bytes)
    btc_address = public_key_to_btc_address(compressed_pubkey)
    segwit_address = public_key_to_segwit_address(compressed_pubkey)

    displayed_btc_key = wif[:-5] + f"<span style='color:red'>{wif[-5:]}</span>"
    st.markdown(f"**BTC 私钥(WIF):** {displayed_btc_key}", unsafe_allow_html=True)
    if st.button("复制 BTC 私钥（不含后5位）"):
        pyperclip.copy(wif[:-5])
        st.success("BTC 私钥已复制（最后5位未复制）")

    st.text_input("BTC 传统地址", btc_address, key="btc_address_input")
    if st.button("复制 BTC 传统地址"):
        pyperclip.copy(btc_address)
        st.success("BTC 传统地址已复制")

    st.text_input("BTC SegWit 地址", segwit_address, key="btc_segwit_input")
    if st.button("复制 BTC SegWit 地址"):
        pyperclip.copy(segwit_address)
        st.success("BTC SegWit 地址已复制")
