#ifndef STORAGE_HPP
#define STORAGE_HPP

#include <string>
using namespace std;

class Storage {
public:
    Storage() {}
    bool saveToFile(const string& data, const string& filename);
    string loadFromFile(const string& filename);
};

#endif
