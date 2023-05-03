#include "../inc/hash/hash.h"

std::shared_ptr<Hash> Hash::create_shared(const std::string& name){
	if(name == "sha2-256" | name == "SHA2-256"){
		return std::make_shared<SHA256>();
	}
	else if(name == "sha2-512" | name == "SHA2-512"){
		return std::make_shared<SHA512>();
	}
	return nullptr;
}

std::unique_ptr<Hash> Hash::create_unique(const std::string& name){
	if(name == "sha2-256" | name == "SHA2-256"){
		return std::make_unique<SHA256>();
	}
	else if(name == "sha2-512" | name == "SHA2-512"){
		return std::make_unique<SHA512>();
	}
	return nullptr;
}
