#include "Network.hpp"
#include <iostream>
using namespace std;

bool Network::uploadToCloud(const string& encryptedText) {
    // ✅ Just show encrypted text in terminal
    cout << "Encrypted text: " << encryptedText << endl;

    // Since no actual upload is done, just return true
    return true;
}
