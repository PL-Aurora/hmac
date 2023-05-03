#ifndef LIBCRYPTO_HASH_SHA_SHA512_H
#define LIBCRYPTO_HASH_SHA_SHA512_H

#include <array>
#include "../hash_function.h"

class SHA512 : public Hash
{
public:
	SHA512() = default;
	~SHA512() = default;

	Hash_Result init();

	Hash_Result update(const unsigned char *in, unsigned long long inlen);

	Hash_Result final(unsigned char *out);

	/**
	 * Funkcja haszująca SHA 512.
	 * @param in tablica przechowująca wiadomosc dla ktorej liczymy hash
	 * @param out tablica, do której zostanie zapisany skrót (64 bajty).
	 * @param inlen, jako długośc wiadomości pomniejszona o 1U (inlen = sizeof msg - 1U)
	 */

	Hash_Result hash(unsigned char *out, const unsigned char *in, unsigned long long inlen);

	/* @reset stanu */
	void clear();

	/* @return nazwa funkcji skrótu */
	const std::string getName() const { return "SHA2-512"; };

	/* @return długość bloku (bajty) */
	std::size_t getBlockSize() const override { return SHA512_BLOCK_LENGTH_BYTES; }

	/* @return długość skrótu (bajty) */
	std::size_t getDigestSize() const override { return SHA512_DIGEST_LENGTH_BYTES; }

private:
	std::array<uint64_t, STATE_LENGTH_BYTES> state{0};
	std::array<uint8_t, SHA512_BLOCK_LENGTH_BYTES> buf{0};
	std::array<uint64_t, 2> count{0};

	void SHA512_Transform(uint64_t state[STATE_LENGTH_BYTES], const uint8_t block[SHA512_BLOCK_LENGTH_BYTES], uint64_t W[TRANSFORM_PAD_BLOCK_LENGTH],
						  uint64_t S[STATE_LENGTH_BYTES]);
	void SHA512_Pad(std::array<uint64_t, TRANSFORM_PAD_BLOCK_LENGTH + STATE_LENGTH_BYTES> &tmp64);
};

void be64enc_vect(unsigned char *dst, const uint64_t *src, size_t len);

void be64dec_vect(uint64_t *dst, const unsigned char *src, size_t len);

#endif // LIBCRYPTO_HASH_SHA_SHA512_H