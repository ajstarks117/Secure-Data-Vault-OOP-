#include <iostream>
#include <fstream>
#include <string>
#include <chrono>   // <-- Added for timing
#include "Encryption.hpp"
#include "Storage.hpp"
#include "Network.hpp"

using namespace std;
using Clock = std::chrono::high_resolution_clock;

// Helper: get AES mode from user
Encryption::AESMode selectMode() {
    int choice;
    cout << "\nSelect AES Mode:\n";
    cout << "1. AES-128\n";
    cout << "2. AES-192\n";
    cout << "3. AES-256\n";
    cout << "Choice: ";
    cin >> choice;
    cin.ignore();
    switch (choice) {
        case 1: return Encryption::AES_128;
        case 2: return Encryption::AES_192;
        default: return Encryption::AES_256;
    }
}

int main() {
    Encryption enc;
    Storage storage;
    Network net;

    string filename = "encrypted.bin";
    char choice;

    while (true) {
        cout << "\n=== Secure Data Vault ===\n";
        cout << "1. Encrypt & Save Text\n";
        cout << "2. View Decrypted Text\n";
        cout << "3. Upload Encrypted Text (simulated)\n";
        cout << "4. Encrypt File\n";
        cout << "5. Decrypt File\n";
        cout << "6. Exit\n";
        cout << "Choice: ";
        cin >> choice;
        cin.ignore();

        // -------------------- OPTION 1: Encrypt & Save Text --------------------
        if (choice == '1') {
            string text, password;
            cout << "Enter text to encrypt: ";
            getline(cin, text);
            cout << "Enter password: ";
            getline(cin, password);

            Encryption::AESMode mode = selectMode();

            // ------ Time Measurement (Encryption) ------
            auto start = Clock::now();
            string encrypted = enc.encrypt(text, password, mode);
            auto end = Clock::now();

            long long enc_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            double speed_encrypt = text.size() / (enc_time / 1e6);

            if (encrypted.empty()) {
                cout << "❌ Encryption failed.\n";
            } else if (storage.saveToFile(encrypted, filename)) {
                cout << "✅ Text encrypted with AES-"
                     << (mode == Encryption::AES_128 ? "128" :
                         mode == Encryption::AES_192 ? "192" : "256")
                     << " and saved to " << filename << "\n";

                cout << "⏱ Encryption Time: " << enc_time << " microseconds\n";
                cout << "⚡ Encryption Speed: " << speed_encrypt << " bytes/sec\n";
            } else {
                cout << "❌ Failed to save.\n";
            }
        }

        // -------------------- OPTION 2: View Decrypted Text --------------------
        else if (choice == '2') {
            string password;
            cout << "Enter password to decrypt: ";
            getline(cin, password);

            string encrypted = storage.loadFromFile(filename);
            if (encrypted.empty()) {
                cout << "❌ No data found.\n";
                continue;
            }

            // ------ Time Measurement (Decryption) ------
            auto start = Clock::now();
            string decrypted = enc.decrypt(encrypted, password, Encryption::AES_256);
            auto end = Clock::now();

            long long dec_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

            if (decrypted.empty()) {
                cout << "❌ Wrong password or corrupted data.\n";
            } else {
                double speed_decrypt = decrypted.size() / (dec_time / 1e6);

                cout << "✅ Decrypted Text:\n" << decrypted << "\n";
                cout << "⏱ Decryption Time: " << dec_time << " microseconds\n";
                cout << "⚡ Decryption Speed: " << speed_decrypt << " bytes/sec\n";
            }
        }

        // -------------------- OPTION 3: Upload Encrypted --------------------
        else if (choice == '3') {
            string encrypted = storage.loadFromFile(filename);
            if (encrypted.empty()) {
                cout << "❌ No data to upload.\n";
                continue;
            }
            if (net.uploadToCloud(encrypted))
                cout << "✅ Encrypted data uploaded (simulated).\n";
            else
                cout << "❌ Upload failed.\n";
        }

        // -------------------- OPTION 4: Encrypt File --------------------
        else if (choice == '4') {
            string filepath, password;
            cout << "Enter file path to encrypt: ";
            getline(cin, filepath);
            cout << "Enter password: ";
            getline(cin, password);
            Encryption::AESMode mode = selectMode();

            ifstream in(filepath, ios::binary);
            if (!in) {
                cout << "❌ Could not open file.\n";
                continue;
            }

            string fileData((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
            in.close();

            // ------ Time Measurement (Encryption) ------
            auto start = Clock::now();
            string encrypted = enc.encrypt(fileData, password, mode);
            auto end = Clock::now();
            long long enc_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            double speed_encrypt = fileData.size() / (enc_time / 1e6);

            if (encrypted.empty()) {
                cout << "❌ File encryption failed.\n";
                continue;
            }

            string outFile = filepath + ".enc";
            if (storage.saveToFile(encrypted, outFile)) {
                cout << "✅ File encrypted and saved as: " << outFile << "\n";
                cout << "⏱ Encryption Time: " << enc_time << " microseconds\n";
                cout << "⚡ Encryption Speed: " << speed_encrypt << " bytes/sec\n";
            } else {
                cout << "❌ Failed to save encrypted file.\n";
            }
        }

        // -------------------- OPTION 5: Decrypt File --------------------
        else if (choice == '5') {
            string filepath, password;
            cout << "Enter encrypted file path (.enc): ";
            getline(cin, filepath);
            cout << "Enter password: ";
            getline(cin, password);

            string encrypted = storage.loadFromFile(filepath);
            if (encrypted.empty()) {
                cout << "❌ Could not read encrypted file.\n";
                continue;
            }

            // ------ Time Measurement (Decryption) ------
            auto start = Clock::now();
            string decrypted = enc.decrypt(encrypted, password, Encryption::AES_256);
            auto end = Clock::now();
            long long dec_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

            if (decrypted.empty()) {
                cout << "❌ Wrong password or corrupted file.\n";
                continue;
            }

            double speed_decrypt = decrypted.size() / (dec_time / 1e6);

            string outFile = filepath;
            if (outFile.size() > 4 && outFile.substr(outFile.size() - 4) == ".enc")
                outFile = outFile.substr(0, outFile.size() - 4);
            outFile += "_decrypted";

            if (storage.saveToFile(decrypted, outFile)) {
                cout << "✅ File decrypted and saved as: " << outFile << "\n";
                cout << "⏱ Decryption Time: " << dec_time << " microseconds\n";
                cout << "⚡ Decryption Speed: " << speed_decrypt << " bytes/sec\n";
            } else {
                cout << "❌ Failed to save decrypted file.\n";
            }
        }

        // -------------------- EXIT --------------------
        else if (choice == '6') {
            cout << "Goodbye!\n";
            break;
        }

        else {
            cout << "Invalid choice.\n";
        }
    }
    return 0;
}
