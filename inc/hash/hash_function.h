#ifndef SUBMODULES_LIBCRYPTO_INCLUDE_HASH_HASH_FUNCTION_H_
#define SUBMODULES_LIBCRYPTO_INCLUDE_HASH_HASH_FUNCTION_H_

#include <memory>
#include "hash/types.h"
#include <exception/libcrypto_exception.h>

#define SHA512_DIGEST_LENGTH_BYTES 64
#define SHA512_BLOCK_LENGTH_BYTES 128
#define SHA256_DIGEST_LENGTH_BYTES 32
#define SHA256_BLOCK_LENGTH_BYTES 64
#define STATE_LENGTH_BYTES 8
#define TRANSFORM_PAD_BLOCK_LENGTH 80

class UnsupportedHashFunction : public LibCryptoException
{
public:
	UnsupportedHashFunction(const std::string &msg) : LibCryptoException(msg) { ; }
};

/**
 * @brief Podstawowa klasa (interfejs) dla wszystkich funkcji skrotu (SHA),
 * @tparam getName() nazwa funkcji skrotu,
 * @tparam getBlockSize rozmiar bloku (w bajtach),
 * @tparam getDigestSize rozmiar skrotu (bajty),
 */

class Hash
{
public:
	virtual ~Hash() = default;

	virtual Hash_Result init() = 0;
	virtual Hash_Result update(const unsigned char *in, unsigned long long inlen) = 0;
	virtual Hash_Result final(unsigned char *out) = 0;
	virtual Hash_Result hash(unsigned char *out, const unsigned char *in, unsigned long long inlen) = 0;
	
	/* @reset stanu */
	virtual void clear() = 0;

	/* @return nazwa funkcji skrótu */
	virtual const std::string getName() const = 0;

	/* @return długość bloku (bajty) */
	virtual std::size_t getBlockSize() const = 0;

	/* @return długość skrótu (bajty) */
	virtual std::size_t getDigestSize() const = 0;

	static std::unique_ptr<Hash> create_unique(const std::string &name);
	static std::shared_ptr<Hash> create_shared(const std::string &name);
};

#endif /* SUBMODULES_LIBCRYPTO_INCLUDE_HASH_HASH_FUNCTION_H_ */
