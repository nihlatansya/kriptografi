import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os
import random

def generate_trng_key(size=16):
    return get_random_bytes(size)

def caesar_cipher_bytes(data, shift, encrypt=True):
    shift = shift if encrypt else -shift
    return bytes((byte + shift) % 256 for byte in data)

def encrypt_file_auto(file_path):
    shift = random.randint(1, 9)
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    caesar_encrypted = caesar_cipher_bytes(plaintext, shift, encrypt=True)
    aes_key = generate_trng_key()
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(caesar_encrypted)
    
    rsa_key = RSA.generate(2048)
    private_key = rsa_key.export_key()
    public_key = rsa_key.publickey().export_key()
    
    output_folder = os.path.dirname(os.path.abspath(__file__))
    private_key_path = os.path.join(output_folder, "private.pem")
    public_key_path = os.path.join(output_folder, "public.pem")
    
    with open(private_key_path, "wb") as f:
        f.write(private_key)
    with open(public_key_path, "wb") as f:
        f.write(public_key)
    
    with open(public_key_path, 'rb') as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    encrypted_file_path = file_path + ".rsa.aes.caesar"
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_aes_key + cipher_aes.nonce + tag + ciphertext + bytes([shift]))
    
    messagebox.showinfo("Sukses", f"File berhasil dienkripsi!\nOutput: {encrypted_file_path}")

def decrypt_file_auto(file_path):
    output_folder = os.path.dirname(os.path.abspath(__file__))
    private_key_path = os.path.join(output_folder, "private.pem")
    
    if not os.path.exists(private_key_path):
        messagebox.showerror("Error", "Kunci privat RSA tidak ditemukan!")
        return
    
    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    
    with open(file_path, 'rb') as f:
        encrypted_aes_key = f.read(256)  # RSA 2048 key size
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read(-1)
        shift = ciphertext[-1]  # Get last byte as shift value
        ciphertext = ciphertext[:-1]  # Remove shift byte from data
    
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    final_plaintext = caesar_cipher_bytes(decrypted_data, shift, encrypt=False)
    decrypted_file_path = file_path.replace(".rsa.aes.caesar", ".decrypted")
    with open(decrypted_file_path, 'wb') as f:
        f.write(final_plaintext)
    
    messagebox.showinfo("Sukses", f"File berhasil didekripsi!\nOutput: {decrypted_file_path}")

def open_file():
    return filedialog.askopenfilename()

root = tk.Tk()
root.title("Enkripsi & Dekripsi File Otomatis")

frame = tk.Frame(root, padx=10, pady=10)
frame.pack(pady=20)

tk.Button(frame, text="Enkripsi File", command=lambda: encrypt_file_auto(open_file())).pack(pady=5)
tk.Button(frame, text="Dekripsi File", command=lambda: decrypt_file_auto(open_file())).pack(pady=5)
tk.Button(frame, text="Keluar", command=root.quit).pack(pady=5)

root.mainloop()