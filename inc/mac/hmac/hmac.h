#ifndef SUBMODULES_LIBCRYPTO_INCLUDE_HASH_HMAC_HMAC_H_
#define SUBMODULES_LIBCRYPTO_INCLUDE_HASH_HMAC_HMAC_H_

#include <array>
#include <type_traits>

#include "../mac.h"
#include "hash_function.h"


template <typename HASH>
class HMAC : public MAC
{
	static_assert(std::is_base_of_v<Hash, HASH>, "Parameter HASH is not base of class Hash");
private:
	HASH octx, ictx;

public:
	HMAC() = default;
	~HMAC();
	
	Hash_Result init(const unsigned char *key, size_t keylen);
	Hash_Result update(const unsigned char *in, unsigned long long inlen);
	Hash_Result final(unsigned char *out);
	/**
	 * Funkcja obliczajaca mac .
	 * @param out tablica, do której zostanie zapisany hmac (dla SHA256 - > 64 bajty).
	 * @param in tablica przechowująca wiadomosc dla ktorej liczymy mac
	 * @param inlen, jako długośc wiadomości
	 * @param key tablica przechowujaca klucz
	 * @param keylen - dlugosc klucza (bajty)
	 */
	Hash_Result mac(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *key, size_t keylen);

	void clear();
	const std::string getName() const { return "HMAC-" + ictx.getName(); }
	std::size_t getBlockSize() const override { return ictx.getBlockSize(); }
	std::size_t getDigestSize() const override { return ictx.getDigestSize(); }
};

#include <mac/hmac/hmac_functions.h>

#endif /* SUBMODULES_LIBCRYPTO_INCLUDE_HASH_HMAC_HMAC_H_ */
