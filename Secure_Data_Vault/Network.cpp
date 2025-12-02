#include "Network.hpp"
#include <iostream>
using namespace std;

bool Network::uploadToCloud(const string& encryptedText) {
    cout << "\n[Encrypted Data - Base64 Encoded]\n";
    cout << encryptedText << "\n";
    return true;
}
