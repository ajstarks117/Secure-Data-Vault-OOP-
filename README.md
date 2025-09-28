# Secure Data Vault: Encrypted Cloud Text Saver

## Overview
Encrypted Cloud Text Saver is a secure text storage tool that encrypts messages locally before uploading them to the cloud.  
This ensures private access and retrieval through decryption.

## Features (Planned)
- AES Encryption (OpenSSL)
- Secure HTTP Upload (libcurl)
- Local storage via SQLite / File I/O
- User-friendly console-based UI
- Cross-platform (Windows/Linux)

## Current Progress 
- [x] OOP Class structure (Encryption, Storage, Network)
- [x] Simple encryption/decryption (XOR-based prototype)
- [x] File storage for encrypted text
- [x] Console UI for interaction
- [ ] AES encryption using OpenSSL
- [ ] Real HTTP upload using libcurl
- [ ] SQLite integration

## Tech Stack
- C++ (OOP for encryption, storage, networking)
- OpenSSL (AES encryption – to be integrated)
- libcurl (HTTP requests – to be integrated)
- SQLite / File I/O for optional local storage

## Project Structure
``` 
EncryptedCloudSaver/
│── main.cpp # Entry point with UI
│── Encryption.hpp / Encryption.cpp # Encryption/Decryption logic
│── Storage.hpp / Storage.cpp # Local storage handling (File/SQLite)
│── Network.hpp / Network.cpp # Cloud upload/download (libcurl + JSONBin)
│── README.md # Project documentation
```

## How to Run
1. Open the project in Code::Blocks
2. Build and Run
3. Follow the on-screen menu

## Future Work
- Integrate AES encryption via OpenSSL
- Add real cloud upload (libcurl)
- Implement local DB storage with SQLite
- Improve UI (maybe GUI with Qt/GTK later)
