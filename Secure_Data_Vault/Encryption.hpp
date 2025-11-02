#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include <string>

class Encryption {
public:
    enum AESMode {
        AES_128,
        AES_192,
        AES_256
    };

    //Encryption() = default;

    std::string encrypt(const std::string& plainText, const std::string& password, AESMode mode);
    std::string decrypt(const std::string& blob, const std::string& password);
};

#endif
