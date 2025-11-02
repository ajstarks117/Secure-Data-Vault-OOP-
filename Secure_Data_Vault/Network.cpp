#include "Network.hpp"
#include <iostream>

bool Network::uploadToCloud(const std::string& encryptedText) {
    std::cout << "[Simulated upload] Encrypted data length: "
              << encryptedText.size() << " bytes\n";
    return true;
}
