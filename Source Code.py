import tkinter as tk
from tkinter import messagebox, scrolledtext
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# --- AES Logic ---

BLOCK_SIZE = 16

def normalize_key(key):
    if len(key) not in [16, 24, 32]:
        return key.ljust(16, '0')[:16]  # Default to 16 bytes padded
    return key

def encrypt_text(plain_text, key):
    key_bytes = normalize_key(key).encode()
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    iv = cipher.iv
    padded = pad(plain_text.encode(), BLOCK_SIZE)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(iv + encrypted).decode()

def decrypt_text(cipher_b64, key):
    try:
        key_bytes = normalize_key(key).encode()
        raw_data = base64.b64decode(cipher_b64)
        iv = raw_data[:BLOCK_SIZE]
        cipher_text = raw_data[BLOCK_SIZE:]
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(cipher_text), BLOCK_SIZE)
        return decrypted.decode()
    except Exception as e:
        return f"Decryption failed: {str(e)}"

# --- Callback Functions ---

def do_encrypt():
    key = key_entry.get()
    plaintext = plaintext_input.get("1.0", tk.END).strip()
    if not key or not plaintext:
        messagebox.showwarning("Input Error", "Please enter both key and plaintext.")
        return
    encrypted = encrypt_text(plaintext, key)
    encrypted_output.delete("1.0", tk.END)
    encrypted_output.insert(tk.END, encrypted)

def do_decrypt():
    key = key_entry.get()
    cipher_b64 = decrypt_input.get("1.0", tk.END).strip()
    if not key or not cipher_b64:
        messagebox.showwarning("Input Error", "Please enter both key and ciphertext.")
        return
    decrypted = decrypt_text(cipher_b64, key)
    decrypted_output.delete("1.0", tk.END)
    decrypted_output.insert(tk.END, decrypted)

# --- GUI Design ---

window = tk.Tk()
window.title("🔐 AES Encryptor - CBC Mode")
window.geometry("580x650")
window.config(bg="#323232")

title_label = tk.Label(window, text="AES Encryption & Decryption", font=("Helvetica", 16, "bold"), bg="#f0f8ff", fg="#333")
title_label.pack(pady=15)

# Key Input
tk.Label(window, text="Secret Key (16/24/32 chars):", font=("Helvetica", 11, "bold"), bg="#f0f8ff").pack(pady=(5, 0))
key_entry = tk.Entry(window, width=50, bg="#c5d2ff", font=("Courier", 10))
key_entry.pack(pady=3)

# Encryption Section
tk.Label(window, text="Plaintext:", font=("Helvetica", 11, "bold"), bg="#f0f8ff").pack(pady=(10, 0))
plaintext_input = scrolledtext.ScrolledText(window, height=5, width=65, bg="#ffffe0", font=("Courier", 10))
plaintext_input.pack(pady=5)

tk.Button(window, text="🔐 Encrypt", command=do_encrypt, bg="#90ee90", fg="black", font=("Helvetica", 10, "bold"), width=15).pack(pady=5)

tk.Label(window, text="Encrypted Output (Base64):", font=("Helvetica", 11, "bold"), bg="#f0f8ff").pack(pady=(10, 0))
encrypted_output = scrolledtext.ScrolledText(window, height=3, width=65,bg="#ffe4e1", font=("Courier", 10))
encrypted_output.pack(pady=5)

# Decryption Section
tk.Label(window, text="Ciphertext to Decrypt (Base64):", font=("Helvetica", 11, "bold"), bg="#f0f8ff").pack(pady=(10, 0))
decrypt_input = scrolledtext.ScrolledText(window, height=3, width=65, bg="#ffe4e1", font=("Courier", 10))
decrypt_input.pack(pady=5)

tk.Button(window, text="🔓 Decrypt", command=do_decrypt, bg="#90ee90", fg="black", font=("Helvetica", 10, "bold"), width=15).pack(pady=5)

tk.Label(window, text="Decrypted Plaintext:", font=("Helvetica", 11, "bold"), bg="#f0f8ff").pack(pady=(10, 0))
decrypted_output = scrolledtext.ScrolledText(window, height=4, width=65,bg="#ffffe0", font=("Courier", 10))
decrypted_output.pack(pady=5)

tk.Label(window, text="© 2025 AES CBC Mode GUI | VIJAY", font=("Helvetica", 9), bg="#f0f8ff", fg="#666").pack(pady=10)

window.mainloop()
