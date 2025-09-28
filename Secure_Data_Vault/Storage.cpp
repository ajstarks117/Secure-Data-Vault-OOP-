#include "Storage.hpp"
#include <fstream>
#include <iostream>
using namespace std;

bool Storage::saveToFile(const string& data, const string& filename) {
    ofstream outFile(filename, ios::binary);
    if (!outFile) return false;
    outFile << data;
    outFile.close();
    return true;
}

string Storage::loadFromFile(const string& filename) {
    ifstream inFile(filename, ios::binary);
    if (!inFile) return "";
    string data((istreambuf_iterator<char>(inFile)),
                istreambuf_iterator<char>());
    inFile.close();
    return data;
}
