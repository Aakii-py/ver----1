# ver----1
cannot be distributed unless the link to this page is included in a easily readable place and credit must go to me

This project is a modern, encrypted password vault built with Python and a beautiful GUI using customtkinter. It allows users to securely store, manage, search, and import passwords, backed by strong cryptographic standards and user-friendly design.

🌟 Key Features
User Authentication with Master Password

Data Encryption using Fernet (AES-based symmetric encryption)

Secure Password-based Key Derivation (PBKDF2HMAC with SHA-256)

Salted Key Derivation for Enhanced Security

Encrypted Data Storage in JSON

CSV Import Support

Regex-Powered Search Functionality

🛡️ Security Strengths
This app is not just user-friendly, it’s also engineered for robust security:

🔑 1. Password-Based Encryption (PBE)
Utilizes PBKDF2HMAC to derive cryptographic keys from user passwords.

Includes 480,000 iterations, significantly slowing down brute-force attacks.

Uses a random 16-byte salt, stored securely in password.key, ensuring the same password generates different keys across installations.

🔒 2. AES Encryption with Fernet
Once the key is derived, all sensitive data (usernames and passwords) are encrypted using Fernet, a symmetric encryption method built on AES in CBC mode with HMAC for authentication.

Encrypted credentials are stored in data.json and are not readable without the correct password and key.

🧪 3. Exception Handling
The decryption logic safely handles any error using fallback messages (<DECRYPTION FAILED>) to prevent app crashes.

🔎 4. Search with Regex Matching
Allows users to perform secure and flexible searches through entries using Python's re module, which supports both exact and fuzzy lookups.

📂 5. Secure Import
Supports importing credentials from CSV and encrypts the data immediately using the current Fernet instance before storing.

✅ Why This App Is Highly Secure
Cryptography Best Practices are followed (e.g., salt + key derivation + AES encryption).

Data is encrypted at rest and only decrypted on-the-fly when needed.

The app never stores plain-text passwords and resists reverse-engineering through proper separation of logic and cryptographic routines.

Even if data.json is stolen, it’s unreadable without the correct master password and the password.key file.

🚀 Final Thoughts
This password vault isn’t just a utility—it’s a serious security-focused application. Whether you’re a privacy enthusiast, developer, or just someone who forgets passwords often, this tool offers top-notch protection and a clean user experience.

