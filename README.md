Overview
FileEncryptGUI encrypts any file using AES-128-GCM authenticated encryption. Passwords are never stored — they are used to derive an AES key via PBKDF2-HMAC-SHA256 with a random salt. Encrypted files carry a 16-byte salt, 12-byte IV, and GCM authentication tag, so tampering is detected at decryption time.

Requirements

Java 11 or later (uses javax.crypto, standard library only)
No external dependencies or build tool needed


Build & Run
bashjavac FileEncryptGUI.java
java FileEncryptGUI

Features
ActionHow it worksBrowseOpens a file picker to choose the target fileEncryptEncrypts the selected file; saves .enc alongside it; stores a Record ID → path mapping in memoryDecrypt by IDLooks up the Record ID in memory and decrypts to decrypted_<id>.binDecrypt from fileOpens any .enc file directly via file picker; decrypts without needing a stored IDList RecordsPrints all in-memory Record ID → encrypted path mappings to the log

Cryptographic Details
ParameterValueCipherAES-128 / GCM / NoPaddingKey derivationPBKDF2WithHmacSHA256, 100 000 iterationsSalt16 bytes, random per encryptionIV / Nonce12 bytes, random per encryptionGCM tag128 bits (authentication + integrity)Output layout[salt 16B][iv 12B][ciphertext + tag]

Usage Walkthrough

Launch the app with java FileEncryptGUI.
Click Browse and select any file.
Enter a unique Record ID (e.g. doc1) and a strong password.
Click Encrypt — a .enc file is created next to the original.
To decrypt, enter the same Record ID and password, then click Decrypt by ID.
Alternatively, use Decrypt from file to pick any .enc file directly.
The log area at the bottom reports success or errors.


Important Notes

Record IDs are stored in memory only — they are lost when the app closes.
Back up your .enc files; losing the password makes recovery impossible.
Decrypted output is always written as .bin — rename as needed.


Project Structure
FileEncryptGUI.java
├── interface  CryptoEngine          — encrypt / decrypt contract
├── class      AesGcmCryptoEngine    — AES-GCM + PBKDF2 implementation
└── class      FileEncryptGUI        — Swing GUI + event handlers

License
MIT — free to use, modify, and distribute.
