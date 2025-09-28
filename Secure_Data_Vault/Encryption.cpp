#include "Encryption.hpp"

string Encryption::encrypt(const string& plainText, char key) {
    string result = plainText;
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] ^= key;  // simple XOR encryption
    }
    return result;
}

string Encryption::decrypt(const string& cipherText, char key) {
    return encrypt(cipherText, key); // XOR is symmetric
}

