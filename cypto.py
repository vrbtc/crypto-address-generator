import hashlib
import ecdsa
import base58
from eth_utils import keccak
import bech32
import tkinter as tk
from tkinter import ttk, messagebox
import pyperclip


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
    witness_program = ripemd160_pk
    segwit_address = bech32.encode("bc", 0, witness_program)
    return segwit_address


def public_key_to_eth_address(uncompressed_public_key):
    pubkey_bytes = uncompressed_public_key[1:]
    address = keccak(pubkey_bytes)[-20:]
    return "0x" + address.hex()


# ---------- GUI 逻辑 ----------
class CryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("多链地址生成器")
        self.root.geometry("750x700")
        self.root.configure(bg="#f5f7fa")
        self.root.resizable(False, False)

        # 设置样式
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # 配置颜色
        self.style.configure('TFrame', background='#f5f7fa')
        self.style.configure('TLabel', background='#f5f7fa', foreground='#2c3e50', font=('Segoe UI', 9))
        self.style.configure('Title.TLabel', background='#f5f7fa', foreground='#2c3e50', font=('Segoe UI', 14, 'bold'))
        self.style.configure('TButton', font=('Segoe UI', 9))
        self.style.configure('Generate.TButton', font=('Segoe UI', 10, 'bold'), background='#27ae60')
        self.style.map('Generate.TButton', background=[('active', '#219653')])
        self.style.configure('Copy.TButton', font=('Segoe UI', 8), width=6)

        # 标题
        title_frame = ttk.Frame(root)
        title_frame.pack(pady=(15, 10), fill='x')

        title = ttk.Label(title_frame, text="🔑 多链地址生成器", style='Title.TLabel')
        title.pack()

        subtitle = ttk.Label(title_frame, text="输入任意文本生成多种加密货币地址", font=('Segoe UI', 9))
        subtitle.pack(pady=(0, 10))

        # 输入区域
        input_frame = ttk.Frame(root, padding=10)
        input_frame.pack(padx=15, pady=5, fill='x')

        # 生成按钮放在输入框上方
        btn_frame = ttk.Frame(input_frame)
        btn_frame.pack(fill='x', pady=(0, 8))

        btn_generate = ttk.Button(btn_frame, text="生成地址", command=self.generate_addresses, style='Generate.TButton')
        btn_generate.pack()

        input_label = ttk.Label(input_frame, text="请输入任意文本（密码、短语等）:")
        input_label.pack(anchor='w', pady=(0, 5))

        self.entry = ttk.Entry(input_frame, width=50, font=("Consolas", 10))
        self.entry.pack(fill='x', pady=5)
        self.entry.bind('<Return>', lambda e: self.generate_addresses())

        # 结果区域
        result_frame = ttk.Frame(root)
        result_frame.pack(padx=15, pady=10, fill='both', expand=True)

        # ETH区域 - 移除标题
        eth_frame = ttk.Frame(result_frame, padding=10)
        eth_frame.pack(fill='x', pady=(0, 10))

        self.eth_private_frame = ttk.Frame(eth_frame)
        self.eth_private_frame.pack(fill='x', pady=5)

        self.eth_address_frame = ttk.Frame(eth_frame)
        self.eth_address_frame.pack(fill='x', pady=5)

        # BTC区域 - 移除标题
        btc_frame = ttk.Frame(result_frame, padding=10)
        btc_frame.pack(fill='x')

        self.btc_private_frame = ttk.Frame(btc_frame)
        self.btc_private_frame.pack(fill='x', pady=5)

        self.btc_address_frame = ttk.Frame(btc_frame)
        self.btc_address_frame.pack(fill='x', pady=5)

        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        status_bar = ttk.Label(root, textvariable=self.status_var, relief='sunken', anchor='w', font=('Segoe UI', 8))
        status_bar.pack(side='bottom', fill='x', padx=1, pady=1)

        # 设置焦点
        self.entry.focus()

    def display_private_key(self, parent, title, value):
        """显示私钥，最后 5 位红色且不可复制"""
        frame = ttk.Frame(parent)
        frame.pack(fill="x", pady=5)

        label = ttk.Label(frame, text=title + ":", font=("Segoe UI", 9, "bold"))
        label.pack(anchor="w")

        # 创建文本框架
        text_frame = ttk.Frame(frame)
        text_frame.pack(fill="x", pady=3)

        # 创建文本框
        text = tk.Text(text_frame, height=1, wrap="none", font=("Consolas", 9),
                       relief="solid", borderwidth=1, padx=4, pady=4)
        text.pack(side="left", fill="x", expand=True)

        # 插入文本
        text.insert("1.0", value[:-5])
        text.insert("end", value[-5:], "red")
        text.tag_config("red", foreground="#e74c3c")
        text.config(state="disabled")

        # 复制按钮
        def copy_key():
            pyperclip.copy(value[:-5])
            self.status_var.set(f"{title} 已复制（最后 5 位未复制）")

        btn = ttk.Button(text_frame, text="复制", command=copy_key, style='Copy.TButton')
        btn.pack(side="right", padx=(3, 0))

    def display_address(self, parent, title, value):
        """显示地址，可以完整复制"""
        frame = ttk.Frame(parent)
        frame.pack(fill="x", pady=5)

        label = ttk.Label(frame, text=title + ":", font=("Segoe UI", 9, "bold"))
        label.pack(anchor="w")

        # 创建输入框架
        input_frame = ttk.Frame(frame)
        input_frame.pack(fill="x", pady=3)

        # 创建只读输入框 - 使用统一的字体大小
        entry = ttk.Entry(input_frame, font=("Consolas", 9))
        entry.insert(0, value)
        entry.config(state="readonly")
        entry.pack(side="left", fill="x", expand=True, padx=(0, 3))

        # 复制按钮
        def copy_address():
            pyperclip.copy(value)
            self.status_var.set(f"{title} 已复制")

        btn = ttk.Button(input_frame, text="复制", command=copy_address, style='Copy.TButton')
        btn.pack(side="right")

    def generate_addresses(self):
        # 清除之前的结果
        for widget in self.eth_private_frame.winfo_children():
            widget.destroy()
        for widget in self.eth_address_frame.winfo_children():
            widget.destroy()
        for widget in self.btc_private_frame.winfo_children():
            widget.destroy()
        for widget in self.btc_address_frame.winfo_children():
            widget.destroy()

        self.status_var.set("正在生成地址...")
        self.root.update()

        user_input = self.entry.get().strip()
        if not user_input:
            messagebox.showwarning("警告", "请输入内容！")
            self.status_var.set("就绪")
            return

        try:
            sha256_result = sha256_hash(user_input)
            private_key_bytes = bytes.fromhex(sha256_result)

            # ETH相关
            self.display_private_key(self.eth_private_frame, "ETH 私钥", sha256_result)

            uncompressed_pubkey = private_key_to_uncompressed_public_key(private_key_bytes)
            eth_address = public_key_to_eth_address(uncompressed_pubkey)
            self.display_address(self.eth_address_frame, "ETH 地址", eth_address)

            # BTC相关
            wif = private_key_to_wif(sha256_result)
            self.display_private_key(self.btc_private_frame, "BTC 私钥 (WIF)", wif)

            compressed_pubkey = private_key_to_compressed_public_key(private_key_bytes)
            btc_address = public_key_to_btc_address(compressed_pubkey)
            self.display_address(self.btc_address_frame, "BTC 传统地址", btc_address)

            segwit_address = public_key_to_segwit_address(compressed_pubkey)
            self.display_address(self.btc_address_frame, "BTC SegWit 地址", segwit_address)

            self.status_var.set("地址生成完成")

        except Exception as e:
            messagebox.showerror("错误", str(e))
            self.status_var.set("错误: " + str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()