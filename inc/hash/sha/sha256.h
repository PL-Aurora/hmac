#ifndef SUBMODULES_LIBCRYPTO_INCLUDE_HASH_SHA_SHA256_H_
#define SUBMODULES_LIBCRYPTO_INCLUDE_HASH_SHA_SHA256_H_

#include <array>
#include "../hash_function.h"

class SHA256 : public Hash
{
public:
	SHA256() = default;
	~SHA256();

	Hash_Result init();
	Hash_Result update(const unsigned char *in, unsigned long long inlen);
	Hash_Result final(unsigned char *out);
	/**
	 * Funkcja haszująca SHA 256.
	 * @param in tablica przechowująca wiadomosc dla ktorej liczymy hash
	 * @param out tablica, do której zostanie zapisany skrót (64 bajty).
	 * @param inlen, dlugosc wiadomosci (in)
	 */
	Hash_Result hash(unsigned char *out, const unsigned char *in, unsigned long long inlen);

	// funkcje wirtualne
	void clear();
	const std::string getName() const { return "sha2-256"; }
	std::size_t getBlockSize() const override { return SHA256_BLOCK_LENGTH_BYTES; }
	std::size_t getDigestSize() const override { return SHA256_DIGEST_LENGTH_BYTES; }

private:
	std::array<uint32_t, STATE_LENGTH_BYTES> state{0};
	std::array<uint8_t, SHA256_BLOCK_LENGTH_BYTES> buf{0};
	uint64_t count{0};

	void SHA256_Transform(uint32_t state[STATE_LENGTH_BYTES], const uint8_t block[SHA256_BLOCK_LENGTH_BYTES],
						  uint32_t W[SHA256_BLOCK_LENGTH_BYTES], uint32_t S[STATE_LENGTH_BYTES]);
	void SHA256_Pad(std::array<uint32_t, SHA256_BLOCK_LENGTH_BYTES + STATE_LENGTH_BYTES> &tmp32);
};

#endif /* SUBMODULES_LIBCRYPTO_INCLUDE_HASH_SHA_SHA256_H_ */
