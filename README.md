# Password Manager

[![Build](https://github.com/YOUR_USERNAME/password-manager/actions/workflows/build.yml/badge.svg)](https://github.com/YOUR_USERNAME/password-manager/actions/workflows/build.yml)

A simple, secure command-line password manager written in C++ using OpenSSL AES-256-CBC encryption. Passwords are stored encrypted in `~/.ssh/password.enc`.

## Features

- **AES-256-CBC encryption** via OpenSSL — all data encrypted at rest
- **Two authentication modes**: SSH private key (automatic) or master password
- **Simple JSON storage** — no external dependencies beyond OpenSSL
- **Cross-platform**: Linux native & Windows via MinGW cross-compilation
- **Single binary** — no runtime dependencies

## Dependencies

- **OpenSSL** (libssl-dev / libcrypto)
- **g++** with C++17 support
- For Windows cross-compile: **mingw-w64** + OpenSSL compiled for MinGW

## Build

### Linux

```bash
# Install dependencies
sudo apt-get install -y libssl-dev g++

# Compile
g++ -std=c++17 -O2 password.cpp -o password -lssl -lcrypto -static-libgcc -static-libstdc++
```

### Windows (cross-compile from Linux)

```bash
# Install mingw-w64
sudo apt-get install -y mingw-w64

# Build OpenSSL for MinGW (one-time)
export OPENSSL_DIR=/usr/local/openssl-mingw64
./Configure mingw64 --prefix=${OPENSSL_DIR} --cross-compile-prefix=x86_64-w64-mingw32- no-shared
make -j$(nproc) && sudo make install

# Compile
x86_64-w64-mingw32-g++ -std=c++17 -O2 password.cpp -o password.exe \
  -I${OPENSSL_DIR}/include -L${OPENSSL_DIR}/lib64 \
  -lssl -lcrypto -static -static-libgcc -static-libstdc++ \
  -lws2_32 -lcrypt32
```

### Download Prebuilt Binaries

Go to the [Releases](https://github.com/YOUR_USERNAME/password-manager/releases) page to download prebuilt binaries for:

- `password-linux-x86_64` — Linux x86_64
- `password-windows-x86_64.exe` — Windows x86_64

## Usage

```bash
# Add a password
./password add <keyword> <account> <password>

# Query password
./password get <keyword>
./password <keyword>           # shortcut

# Update password
./password update <keyword> <account> <new_password>

# Delete a specific account
./password delete <keyword> <account>

# Delete an entire keyword
./password delete <keyword>

# List all keywords
./password list
```

### Examples

```bash
# Add GitHub credentials
./password add github myemail@example.com MyP@ssw0rd

# Add with special characters (use single quotes)
./password add server root 'p@ss/!special'

# Retrieve GitHub credentials
./password github
# or
./password get github
```

## Authentication

This tool supports two authentication methods:

### 1. SSH Key Authentication (Recommended)

If `~/.ssh/id_ed25519` or `~/.ssh/id_rsa` exists, the tool automatically uses it as the encryption key. No password prompt needed.

```bash
# Generate an SSH key if you don't have one
ssh-keygen -t ed25519
```

### 2. Manual Master Password

If no SSH key is found, you'll be prompted to enter a master password each time.

## How It Works

1. **Key Derivation**: The master key is derived from your SSH key (or entered password) using SHA-256.
2. **Encryption**: Data is encrypted with AES-256-CBC. A random 16-byte IV is generated for each save.
3. **Storage**: `IV + ciphertext` is written to `~/.ssh/password.enc`.

## Security Notes

- The password file is stored alongside your SSH keys in `~/.ssh/` (permissions 0700 recommended).
- Never share your SSH private key — anyone with it can decrypt the password vault.
- Consider backing up `~/.ssh/password.enc` if you store important credentials.
- The tool does NOT have a password generator — use a strong, unique password for each account.

## License

MIT
