🧩 Custom Hash Function GUI — Compare Custom Hash with SHA-256
🔍 Overview

This project demonstrates the fundamentals of hashing through a Python GUI built with tkinter.
It allows users to:
Generate a custom-designed hash value (non-cryptographic, educational hash).
Compare it with the standard SHA-256 hash function from Python’s hashlib.
Compute the Hamming distance (bit difference) between both hashes to show how small input changes cause big output changes — a key property of hash functions.

⚙️ Features
✅ GUI-based (no need for terminal input)
✅ Custom hashing algorithm using:
ASCII encoding and character manipulation
Modular arithmetic
Bit rotations and state mixing
✅ SHA-256 comparison for reference
✅ Hamming distance calculation (bitwise difference)
✅ Educational purpose — demonstrates avalanche effect in hashing

🧮 How It Works
The GUI lets you:
Enter any text.
Click “Compute Hash”.
Instantly view:
Your custom hash output (toy hash)

The SHA-256 hash of the same text

The Hamming distance (how many bits differ between both)
