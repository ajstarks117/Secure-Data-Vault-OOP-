#include <iostream>
#include <openssl/evp.h>

using namespace std;

int main() {
    cout << "OpenSSL test: " << OpenSSL_version(OPENSSL_VERSION) << endl;
    return 0;
}

