#ifndef SUBMODULES_LIBCRYPTO_INCLUDE_HASH_HMAC_HMAC_FUNCTIONS_H_
#define SUBMODULES_LIBCRYPTO_INCLUDE_HASH_HMAC_HMAC_FUNCTIONS_H_

#include <cstring>

#include "`../mac/hmac/hmac.h"
#include "`../memory/mem_ops.h"

template <typename T>
void HMAC<T>::clear()
{
    ictx.clear();
    octx.clear();
}

template <typename T>
HMAC<T>::~HMAC()
{
    clear();
}

template <typename T>
Hash_Result HMAC<T>::init(const unsigned char *key, size_t keylen)
{
    unsigned char pad[ictx.getBlockSize()];
    unsigned char khash[ictx.getDigestSize()];
    size_t i;
    if (keylen > ictx.getBlockSize())
    {
        ictx.init();
        ictx.update(key, keylen);
        ictx.final(khash);
        key = khash;
        keylen = ictx.getDigestSize();
    }
    ictx.init();
    std::memset(pad, 0x36, ictx.getBlockSize());
    for (i = 0; i < keylen; i++)
    {
        pad[i] ^= key[i];
    }
    ictx.update(pad, ictx.getBlockSize());

    octx.init();
    std::memset(pad, 0x5c, ictx.getBlockSize());
    for (i = 0; i < keylen; i++)
    {
        pad[i] ^= key[i];
    }
    octx.update(pad, ictx.getBlockSize());
    // std::memset(pad, 0, ictx.getBlockSize());
    // std::memset(khash, 0, ictx.getDigestSize());
    zeroize(pad, sizeof(pad));
    zeroize(khash, sizeof(khash));

    return Hash_Result::SUCCES_INIT;
}

template <typename T>
Hash_Result HMAC<T>::update(const unsigned char *in, unsigned long long inlen)
{
    ictx.update(in, inlen);

    return Hash_Result::SUCCES_UPDATE;
}

template <typename T>
Hash_Result HMAC<T>::final(unsigned char *out)
{
    unsigned char ihash[ictx.getDigestSize()];
    ictx.final(ihash);
    octx.update(ihash, ictx.getDigestSize());
    octx.final(out);
    zeroize(ihash, sizeof(ihash));
    return Hash_Result::SUCCES_FINAL;
}

template <typename T>
Hash_Result HMAC<T>::mac(unsigned char *out, const unsigned char *in,
                         unsigned long long inlen, const unsigned char *key, size_t keylen)
{
    init(key, keylen);
    update(in, inlen);
    final(out);

    return Hash_Result::SUCCES_HASH;
}

#endif /* SUBMODULES_LIBCRYPTO_INCLUDE_HASH_HMAC_HMAC_FUNCTIONS_H_ */
