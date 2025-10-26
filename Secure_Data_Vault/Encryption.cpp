#include "Encryption.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <vector>
#include <cstring>
#include <iostream>

namespace {
    constexpr int SALT_LEN = 16;
    constexpr int IV_LEN   = 16;
    constexpr int PBKDF2_ITER = 100000;

    const EVP_CIPHER* getCipher(Encryption::AESMode mode) {
        switch (mode) {
            case Encryption::AES_128: return EVP_aes_128_cbc();
            case Encryption::AES_192: return EVP_aes_192_cbc();
            case Encryption::AES_256: return EVP_aes_256_cbc();
            default: return EVP_aes_256_cbc();
        }
    }

    int getKeyLength(Encryption::AESMode mode) {
        switch (mode) {
            case Encryption::AES_128: return 16;
            case Encryption::AES_192: return 24;
            case Encryption::AES_256: return 32;
            default: return 32;
        }
    }

    void printErrors() {
        unsigned long err;
        while ((err = ERR_get_error()) != 0) {
            char buf[256];
            ERR_error_string_n(err, buf, sizeof(buf));
            std::cerr << "OpenSSL error: " << buf << "\n";
        }
    }
}

std::string Encryption::encrypt(const std::string& plainText, const std::string& password, AESMode mode) {
    if (password.empty()) return {};

    unsigned char salt[SALT_LEN], iv[IV_LEN];
    RAND_bytes(salt, SALT_LEN);
    RAND_bytes(iv, IV_LEN);

    int keyLen = getKeyLength(mode);
    unsigned char key[32]; // max 256 bits

    if (PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(),
                          salt, SALT_LEN,
                          PBKDF2_ITER,
                          EVP_sha256(), keyLen, key) != 1) {
        printErrors();
        return {};
    }

    const EVP_CIPHER* cipher = getCipher(mode);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv) != 1) {
        printErrors();
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    std::vector<unsigned char> ciphertext(plainText.size() + EVP_CIPHER_block_size(cipher));
    int len = 0, total = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          reinterpret_cast<const unsigned char*>(plainText.data()), (int)plainText.size()) != 1) {
        printErrors();
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    total = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        printErrors();
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    total += len;

    EVP_CIPHER_CTX_free(ctx);

    std::string out;
    out.resize(SALT_LEN + IV_LEN + total + 1);
    out[0] = static_cast<char>(mode); // store AES mode in first byte
    memcpy(&out[1], salt, SALT_LEN);
    memcpy(&out[1 + SALT_LEN], iv, IV_LEN);
    memcpy(&out[1 + SALT_LEN + IV_LEN], ciphertext.data(), total);

    return out;
}

std::string Encryption::decrypt(const std::string& blob, const std::string& password, AESMode /*modeParam*/) {
    if (blob.size() < 1 + SALT_LEN + IV_LEN) return {};

    AESMode mode = static_cast<AESMode>(blob[0]);
    const unsigned char* salt = (const unsigned char*)&blob[1];
    const unsigned char* iv = salt + SALT_LEN;
    const unsigned char* ciphertext = iv + IV_LEN;
    int ciphertext_len = (int)blob.size() - (1 + SALT_LEN + IV_LEN);

    int keyLen = getKeyLength(mode);
    unsigned char key[32];
    if (PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(),
                          salt, SALT_LEN, PBKDF2_ITER,
                          EVP_sha256(), keyLen, key) != 1) {
        printErrors();
        return {};
    }

    const EVP_CIPHER* cipher = getCipher(mode);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv) != 1) {
        printErrors();
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    std::vector<unsigned char> plaintext(ciphertext_len + EVP_CIPHER_block_size(cipher));
    int len = 0, total = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    total = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {}; // wrong password or tampered data
    }
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string((char*)plaintext.data(), total);
}
