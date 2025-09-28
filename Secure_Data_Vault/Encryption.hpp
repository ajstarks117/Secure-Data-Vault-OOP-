#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include <string>
using namespace std;

class Encryption {
public:
    Encryption() {}
    string encrypt(const string& plainText, char key);
    string decrypt(const string& cipherText, char key);
};

#endif
