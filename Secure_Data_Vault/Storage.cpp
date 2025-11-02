#include "Storage.hpp"
#include <fstream>
#include <iostream>

bool Storage::saveToFile(const std::string& data, const std::string& filename) {
    std::ofstream outFile(filename, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open()) {
        std::cerr << "Error: Unable to open " << filename << " for writing.\n";
        return false;
    }
    outFile.write(data.data(), data.size());
    if (!outFile.good()) {
        std::cerr << "Error: Failed to write data to " << filename << ".\n";
        return false;
    }
    return true;
}

std::string Storage::loadFromFile(const std::string& filename) {
    std::ifstream inFile(filename, std::ios::binary);
    if (!inFile.is_open()) {
        std::cerr << "Error: Unable to open " << filename << " for reading.\n";
        return "";
    }
    std::string data((std::istreambuf_iterator<char>(inFile)),
                     std::istreambuf_iterator<char>());
    return data;
}
