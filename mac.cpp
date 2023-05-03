#include "inc/mac/mac.h"
#include "inc/hash/hash.h"

#include <algorithm>

std::unique_ptr<MAC> MAC::create_unique(const std::string& mac_name){
    std::string tmp_mac_name{mac_name};
    std::transform(mac_name.begin(), mac_name.end(), tmp_mac_name.begin(), ::tolower);
    if(tmp_mac_name == "hmac-sha2-256"){
        return std::make_unique<HMAC<SHA256>>();
    }
    return nullptr;
}

std::shared_ptr<MAC> MAC::create_shared(const std::string& mac_name){
    std::string tmp_mac_name{mac_name};
    std::transform(mac_name.begin(), mac_name.end(), tmp_mac_name.begin(), ::tolower);
    if(tmp_mac_name == "hmac-sha2-256"){
        return std::make_shared<HMAC<SHA256>>();
    }
    return nullptr;
}
