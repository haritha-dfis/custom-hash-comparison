import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import struct

# =========================
#  Custom Toy Hash Function
# =========================
def rotl32(x, r):
    return ((x << r) & 0xFFFFFFFF) | (x >> (32 - r))

def toy_hash(plaintext: str, out_len_hex=32) -> str:
    data = plaintext.encode('utf-8')
    s0, s1, s2, s3 = 0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344
    state = [s0, s1, s2, s3]
    primes = [0x9E3779B1, 0x85EBCA6B, 0xC2B2AE35]
    block_size = 8

    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if len(block) < block_size:
            block = block + b'\x80' + b'\x00' * (block_size - len(block) - 1)
        m0 = struct.unpack_from('<I', block, 0)[0]
        m1 = struct.unpack_from('<I', block, 4)[0]

        state[0] = (state[0] + (m0 ^ primes[0])) & 0xFFFFFFFF
        state[1] = (state[1] ^ (m1 + primes[1])) & 0xFFFFFFFF
        state[2] = (state[2] + rotl32(state[0] ^ m1, 7)) & 0xFFFFFFFF
        state[3] = (state[3] ^ rotl32(state[1] + m0, 11)) & 0xFFFFFFFF
        state[0] ^= ((state[0] << 5) & 0xFFFFFFFF) ^ (state[1] >> 3)
        state[1] = (state[1] + ((state[2] << 7) & 0xFFFFFFFF)) & 0xFFFFFFFF
        state[2] ^= state[3] ^ primes[2]
        state[3] = (state[3] + state[0]) & 0xFFFFFFFF

    for _ in range(6):
        a, b, c, d = state
        a = (a ^ rotl32(b + primes[0], 3) + ((c >> 5) | (d << 27))) & 0xFFFFFFFF
        b = (b + rotl32(c ^ primes[1], 7) ^ ((d << 11) & 0xFFFFFFFF)) & 0xFFFFFFFF
        c = (c ^ rotl32(d + primes[2], 13) + (a >> 2)) & 0xFFFFFFFF
        d = (d + rotl32(a ^ primes[0], 17) ^ (b >> 3)) & 0xFFFFFFFF
        state = [a, b, c, d]

    digest_bytes = b''.join(struct.pack('<I', w) for w in state)
    return digest_bytes.hex()[:out_len_hex]


def hamming_distance_bits(a_hex, b_hex):
    a_bits = bin(int(a_hex, 16))[2:].zfill(len(a_hex)*4)
    b_bits = bin(int(b_hex, 16))[2:].zfill(len(b_hex)*4)
    return sum(x != y for x, y in zip(a_bits, b_bits))


# =========================
#  GUI Logic
# =========================
def compute_hash():
    text = input_text.get("1.0", "end").strip()
    if not text:
        messagebox.showwarning("Empty Input", "Please enter some text!")
        return

    my_hash = toy_hash(text)
    sha_hash = hashlib.sha256(text.encode()).hexdigest()
    ham_bits = hamming_distance_bits(my_hash, sha_hash[:32])

    custom_hash_output.delete("1.0", "end")
    sha_output.delete("1.0", "end")
    custom_hash_output.insert("end", my_hash)
    sha_output.insert("end", sha_hash)

    hamming_label.config(
        text=f"Hamming Distance (first 128 bits): {ham_bits} / 128 bits"
    )


# =========================
#  Tkinter GUI Setup
# =========================
root = tk.Tk()
root.title("Comparing custom hash and SHA-256 ")
root.geometry("800x600")
root.resizable(False, False)

style = ttk.Style()
style.configure("TLabel", font=("Segoe UI", 11))
style.configure("TButton", font=("Segoe UI", 11))

# Input area
ttk.Label(root, text="Enter text to hash:").pack(pady=5)
input_text = tk.Text(root, height=5, width=90)
input_text.pack(pady=5)

ttk.Button(root, text="Compute Hash", command=compute_hash).pack(pady=10)

# Output: custom hash
ttk.Label(root, text="Custom Hash:").pack(pady=2)
custom_hash_output = tk.Text(root, height=2, width=90)
custom_hash_output.pack(pady=5)

# Output: SHA-256
ttk.Label(root, text="SHA-256 Hash:").pack(pady=2)
sha_output = tk.Text(root, height=2, width=90)
sha_output.pack(pady=5)

# Output: Hamming distance
hamming_label = ttk.Label(root, text="", foreground="blue", font=("Segoe UI", 11, "bold"))
hamming_label.pack(pady=10)

root.mainloop()
