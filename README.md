# 🔐 Chunky Encryption

A secure and simple CLI tool written in Rust for encrypting and decrypting files or directories using AES-GCM. Designed for performance, reliability, and clean error handling.

---

## ✨ Features

- 🔒 AES-256 GCM encryption/decryption
- 🗂️ Supports both single files and whole directories (via archiving)
- 🔑 Auto-generates a 32-byte master key for encryption
- 📁 Custom metadata file support
- 🚫 Graceful error handling with descriptive messages
- 🧪 Built with clean, maintainable Rust idioms
- 🔐 Each chunk of data is encrypted with a unique randomly generated key and nonce for enhanced security

---

## 🚀 Usage

### 🔧 Build

```bash
cargo build --release
```

### 🧬 Encrypt

```bash
./chunky-encryption --key master.key --input test.txt --output chunks --meta keychain.bin   --encrypt
```

This will:
- Auto-generate a 32-byte master key and save it to the provided path (--key) in no-encrypted format.
- Archive the input file into .tar file.
- Encrypt each data chunk of .tar file with a unique key and nonce and save it to output directory using AES256.
- Delete the .tar file.
- Encrypt metadata used for data chunk encrpytion using master key with AES256.
- Save encrypted metadata (nonce, tag, etc.) to the `--meta` path.


### 🧬 Encrypt directory

```bash
./chunky-encryption --key master.key --input test_dir/ --output chunks --meta keychain.bin   --encrypt --directory
```

This will:
- Auto-generate a 32-byte master key and save it to the provided path (--key) in no-encrypted format.
- Archive the input directory to .tar file.
- Encrypt each data chunk of .tar file with a unique key and nonce and save it to output directory using AES256.
- Delete the .tar file.
- Encrypt metadata used for data chunk encrpytion using master key with AES256.
- Save encrypted metadata (nonce, tag, etc.) to the `--meta` path.

### Output 📁
<pre>
[ Encryption Output Structure ]
.
├── chunks/                   # Folder containing encrypted file chunks
│   ├── chunk_0.enc
│   ├── chunk_1.enc
│   ├── chunk_2.enc
│   └── ...                   # More encrypted chunks
│
├── keychain.bin              # Keychain file (encrypted with master.key)
└── master.key                # Master key used to encrypt/decrypt keychain.bin
</pre>


### 🔓 Decrypt (file or directory)

```bash
./chunky-encryption --key master.key --input chunks/ --output decrypted.<depends_on_encrypted_file> --meta keychain.bin
```

This will:
- Load your existing 32-byte master key.
- Load your existing encrypted keychain.bin.
- Decrypt keychain.bin using master key.
- Decrypt the input directory file chunks using decrypted kaychain and restore the original content. (* --output >> file format depends on encrypted input/ if encrypted with --directory flag, output will be .tar file )

---

## 📄 Command-line Arguments

| Flag          | Description                                   |
|---------------|-----------------------------------------------|
| `--encrypt`   | Enable encryption mode flag                   |
| `--input`     | Path to file or directory to use              |
| `--output`    | Output path                                   |
| `--meta`      | Path to metadata key-chain file               |
| `--key`       | Path to master key file                       |
| `--directory` | Treat input as a directory flag               |

---

## ❗ Error Handling

This tool uses a custom error enum `EncryptionError` with clear categories (e.g., file errors, crypting errors). All critical failures are logged with context and will exit cleanly with:

```bash
[ ERR ] Reason of failure: <description>
```

---

## 🔐 Security Notes

- Your master key must be **32 bytes** exactly.
- Do **not** reuse metadata keychain or master key across different files.
- Keep both the master key and metadata keychain safe and separated — **losing them will make decryption impossible**.
- Each chunk is encrypted with a **different random key and nonce**, increasing security by minimizing the risk if one chunk is compromised — **losing even one of chunk data will make decryption impossible**.

---

## 📦 Dependencies

- `aes-gcm`
- `rand`
- `clap`
- `bincode`
- `tar`

---

## 📜 License

MIT License

---

## 👤 Ransei

Made with ❤️ using Rust.
