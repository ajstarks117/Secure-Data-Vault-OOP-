#include <iostream>
#include "Encryption.hpp"
#include "Storage.hpp"
#include "Network.hpp"
using namespace std;

int main() {
    Encryption enc;
    Storage storage;
    Network net;

    const string filename = "encrypted.txt";
    char choice;
    char key = 'K'; // simple XOR key for demo

    while(true) {
        cout << "\n=== Secure Data Vault ===\n";
        cout << "1. Encrypt & Save Text\n";
        cout << "2. View Decrypted Text\n";
        cout << "3. View Encrypted Text\n";
        cout << "4. Exit\n";
        cout << "Choice: ";
        cin >> choice;
        cin.ignore();

        if(choice == '1') {
            string text;
            cout << "Enter text to encrypt: ";
            getline(cin, text);
            string encrypted = enc.encrypt(text, key);
            if(storage.saveToFile(encrypted, filename))
                cout << "Text encrypted and saved locally.\n";
            else
                cout << "Failed to save text.\n";
        }
        else if(choice == '2') {
            string encrypted = storage.loadFromFile(filename);
            if(encrypted.empty())
                cout << "No data found.\n";
            else {
                string decrypted = enc.decrypt(encrypted, key);
                cout << "Decrypted Text: " << decrypted << "\n";
            }
        }
        else if(choice == '3') {
            string encrypted = storage.loadFromFile(filename);
            if(encrypted.empty())
                cout << "No data to upload.\n";
            else
                net.uploadToCloud(encrypted);
        }
        else if(choice == '4') {
            break;
        }
        else {
            cout << "Invalid choice.\n";
        }
    }
    return 0;
}
