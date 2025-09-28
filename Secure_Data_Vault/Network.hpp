#ifndef NETWORK_HPP
#define NETWORK_HPP

#include <string>
using namespace std;

class Network {
public:
    bool uploadToCloud(const string& encryptedText);
};

#endif
