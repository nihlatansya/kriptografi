import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os
import random

# Membuat jendela utama GUI
root = tk.Tk()
root.title("Enkripsi & Dekripsi File Otomatis")

# Fungsi log
def log_message(message):
    log_text.insert(tk.END, message + "\n")
    log_text.see(tk.END)
    print(message)

# Widget log Text area
log_frame = tk.Frame(root)
log_frame.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
log_text = tk.Text(log_frame, height=15, wrap=tk.WORD)
log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
scrollbar = tk.Scrollbar(log_frame, command=log_text.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
log_text.config(yscrollcommand=scrollbar.set)

# Fungsi bantu
def generate_trng_key(size=16):
    key = get_random_bytes(size)
    log_message(f"[DEBUG] AES Key (TRNG): {key.hex()}")
    return key

def caesar_cipher_bytes(data, shift, encrypt=True):
    shift = shift if encrypt else -shift
    result = bytes((byte + shift) % 256 for byte in data)
    log_message(f"[DEBUG] Caesar {'Encrypted' if encrypt else 'Decrypted'} Data (first 64 bytes): {result[:64].hex()}")
    return result

def encrypt_file_auto(file_path):
    shift = random.randint(1, 9)
    log_message(f"[DEBUG] Caesar Shift: {shift}")

    with open(file_path, 'rb') as f:
        plaintext = f.read()
    log_message(f"[DEBUG] Original File Data (first 64 bytes): {plaintext[:64].hex()}")

    caesar_encrypted = caesar_cipher_bytes(plaintext, shift, encrypt=True)
    aes_key = generate_trng_key()
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(caesar_encrypted)

    log_message(f"[DEBUG] AES Nonce: {cipher_aes.nonce.hex()}")
    log_message(f"[DEBUG] AES Tag: {tag.hex()}")
    log_message(f"[DEBUG] AES Ciphertext (first 64 bytes): {ciphertext[:64].hex()}")

    rsa_key = RSA.generate(2048)
    private_key = rsa_key.export_key()
    public_key = rsa_key.publickey().export_key()

    log_message(f"[DEBUG] RSA Private Key: {private_key[:64].decode(errors='ignore')}...")
    log_message(f"[DEBUG] RSA Public Key: {public_key[:64].decode(errors='ignore')}...")

    base_filename = os.path.splitext(os.path.basename(file_path))[0]
    output_folder = os.path.dirname(os.path.abspath(file_path))
    private_key_path = os.path.join(output_folder, f"{base_filename}_private.pem")
    public_key_path = os.path.join(output_folder, f"{base_filename}_public.pem")

    with open(private_key_path, "wb") as f:
        f.write(private_key)
    with open(public_key_path, "wb") as f:
        f.write(public_key)

    cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey())
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    log_message(f"[DEBUG] Encrypted AES Key (RSA): {encrypted_aes_key.hex()}")

    original_filename = os.path.basename(file_path)
    encrypted_file_path = file_path + ".encrypted"

    with open(encrypted_file_path, 'wb') as f:
        f.write(len(original_filename).to_bytes(2, 'big'))
        f.write(original_filename.encode('utf-8'))
        f.write(encrypted_aes_key)
        f.write(cipher_aes.nonce)
        f.write(tag)
        f.write(ciphertext)
        f.write(bytes([shift]))

    messagebox.showinfo("Sukses", f"File berhasil dienkripsi!\nOutput: {encrypted_file_path}")
    log_message(f"[INFO] File terenkripsi disimpan di: {encrypted_file_path}")

def decrypt_file_auto(file_path):
    with open(file_path, 'rb') as f:
        filename_len = int.from_bytes(f.read(2), 'big')
        original_filename = f.read(filename_len).decode('utf-8')

        encrypted_aes_key = f.read(256)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read(-1)
        shift = ciphertext[-1]
        ciphertext = ciphertext[:-1]

    log_message(f"[DEBUG] Encrypted AES Key (from file): {encrypted_aes_key.hex()}")
    log_message(f"[DEBUG] Nonce (from file): {nonce.hex()}")
    log_message(f"[DEBUG] Tag (from file): {tag.hex()}")
    log_message(f"[DEBUG] Caesar Shift (from file): {shift}")
    log_message(f"[DEBUG] AES Ciphertext (from file, first 64 bytes): {ciphertext[:64].hex()}")

    base_filename = os.path.splitext(original_filename)[0]
    output_folder = os.path.dirname(os.path.abspath(file_path))
    private_key_path = os.path.join(output_folder, f"{base_filename}_private.pem")

    if not os.path.exists(private_key_path):
        messagebox.showerror("Error", f"Kunci privat RSA untuk '{original_filename}' tidak ditemukan!")
        return

    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read())

    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    log_message(f"[DEBUG] Decrypted AES Key (with RSA): {aes_key.hex()}")

    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    log_message(f"[DEBUG] Decrypted Data from AES (first 64 bytes): {decrypted_data[:64].hex()}")

    final_plaintext = caesar_cipher_bytes(decrypted_data, shift, encrypt=False)
    log_message(f"[DEBUG] Final Decrypted Plaintext (first 64 bytes): {final_plaintext[:64].hex()}")

    decrypted_file_path = os.path.join(
        os.path.dirname(file_path),
        f"{os.path.splitext(original_filename)[0]}_decrypted{os.path.splitext(original_filename)[1]}"
    )

    with open(decrypted_file_path, 'wb') as f:
        f.write(final_plaintext)

    messagebox.showinfo("Sukses", f"File berhasil didekripsi!\nOutput: {decrypted_file_path}")
    log_message(f"[INFO] File hasil dekripsi disimpan di: {decrypted_file_path}")

# Fungsi untuk membuka jendela pilih file
def open_file():
    return filedialog.askopenfilename()

# Buat frame tombol-tombol
frame = tk.Frame(root, padx=10, pady=10)
frame.pack()

tk.Button(frame, text="Enkripsi File", command=lambda: encrypt_file_auto(open_file())).pack(pady=5)
tk.Button(frame, text="Dekripsi File", command=lambda: decrypt_file_auto(open_file())).pack(pady=5)
tk.Button(frame, text="Keluar", command=root.quit).pack(pady=5)

# Jalankan aplikasi GUI
root.mainloop()