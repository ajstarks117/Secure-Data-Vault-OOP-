#include "Network.hpp"
#include <curl/curl.h>
#include <iostream>
using namespace std;

bool Network::uploadToCloud(const string& encryptedText) {
    CURL* curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "X-Master-Key: YOUR_JSONBIN_API_KEY"); // replace with your API key

        string jsonData = "{\"text\":\"" + encryptedText + "\"}";

        curl_easy_setopt(curl, CURLOPT_URL, "https://api.jsonbin.io/v3/b");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());

        res = curl_easy_perform(curl);
        if(res != CURLE_OK)
            cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << "\n";
        else
            cout << "Encrypted text uploaded to cloud successfully!\n";

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
    curl_global_cleanup();
    return (res == CURLE_OK);
}
