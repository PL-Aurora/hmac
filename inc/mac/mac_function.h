#ifndef LIBCRYPTO_MAC_FUNCTION_H
#define LIBCRYPTO_MAC_FUNCTION_H

#include <array>
#include <memory>

#include "hash/types.h"

class MAC
{
public:
	using Status = Hash_Result;

	MAC() = default;
	virtual ~MAC() {}

	virtual Status init(const unsigned char *key, size_t keylen) = 0;
	virtual Status update(const unsigned char *in, unsigned long long inlen) = 0;
	virtual Status final(unsigned char *out) = 0;
	/**
	 * Funkcja obliczajaca mac .
	 * @param out tablica, do której zostanie zapisany hmac (dla SHA256 - > 64 bajty).
	 * @param in tablica przechowująca wiadomosc dla ktorej liczymy mac
	 * @param inlen, jako długośc wiadomości
	 * @param key tablica przechowujaca klucz
	 * @param keylen - dlugosc klucza (bajty)
	 */
	virtual Status mac(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *key, size_t keylen) = 0;

	// f wirtualne
	virtual void clear() = 0;
	virtual const std::string getName() const = 0;
	virtual std::size_t getBlockSize() const = 0;
	virtual std::size_t getDigestSize() const = 0;

	static std::unique_ptr<MAC> create_unique(const std::string &name);
	static std::shared_ptr<MAC> create_shared(const std::string &mac_name);
};

#endif /* LIBCRYPTO_MAC_FUNCTION_H */
