#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../inc/hash/sha/sha512.h"

void SHA512::clear(){
	//hash512 = nullptr;
}

Hash_Result SHA512::init()
{
    static const uint64_t initialState[STATE_LENGTH_BYTES] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
        0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

    count[0] = count[1] = (uint64_t)0U;
    memcpy(&state, initialState, sizeof initialState);

    return Hash_Result::SUCCES_INIT;
}

Hash_Result SHA512::update(const unsigned char *in, unsigned long long inlen)
{
    uint64_t tmp64[TRANSFORM_PAD_BLOCK_LENGTH + STATE_LENGTH_BYTES];
    uint64_t bitlen[2];
    unsigned long long i;
    unsigned long long r;

    if (inlen <= 0U)
    {
        return Hash_Result::ERROR_UPDATE;
    }
    r = (unsigned long long)((count[1] >> 3) & 0x7f);

    bitlen[1] = ((uint64_t)inlen) << 3;
    bitlen[0] = ((uint64_t)inlen) >> 61;

    if ((count[1] += bitlen[1]) < bitlen[1])
    {
        count[0]++;
    }

    count[0] += bitlen[0];
    if (inlen < SHA512_BLOCK_LENGTH_BYTES - r)
    {
        for (i = 0; i < inlen; i++)
        {
            buf[r + i] = in[i];
        }
        return Hash_Result::ERROR_UPDATE;
    }
    for (i = 0; i < SHA512_BLOCK_LENGTH_BYTES - r; i++)
    {
        buf[r + i] = in[i];
    }
    SHA512_Transform(state.data(), buf.data(), &tmp64[0], &tmp64[TRANSFORM_PAD_BLOCK_LENGTH]);
    in += SHA512_BLOCK_LENGTH_BYTES - r;
    inlen -= SHA512_BLOCK_LENGTH_BYTES - r;

    while (inlen >= SHA512_BLOCK_LENGTH_BYTES)
    {
        SHA512_Transform(state.data(), in, &tmp64[0], &tmp64[TRANSFORM_PAD_BLOCK_LENGTH]);
        in += SHA512_BLOCK_LENGTH_BYTES;
        inlen -= SHA512_BLOCK_LENGTH_BYTES;
    }
    inlen &= SHA512_BLOCK_LENGTH_BYTES - 1;
    for (i = 0; i < inlen; i++)
    {
        buf[i] = in[i];
    }
    memset(tmp64, 0, TRANSFORM_PAD_BLOCK_LENGTH + STATE_LENGTH_BYTES);
    return Hash_Result::SUCCES_UPDATE;
}

Hash_Result SHA512::final(unsigned char *out)
{
    std::array<uint64_t, TRANSFORM_PAD_BLOCK_LENGTH + STATE_LENGTH_BYTES> tmp64;
    SHA512_Pad(tmp64);
    be64enc_vect(out, state.data(), SHA512_DIGEST_LENGTH_BYTES);
    memset(tmp64.data(), 0, TRANSFORM_PAD_BLOCK_LENGTH + STATE_LENGTH_BYTES);
    memset(state.data(), 0, STATE_LENGTH_BYTES);

    return Hash_Result::SUCCES_FINAL;
}

Hash_Result SHA512::hash(unsigned char *out, const unsigned char *in,
                         unsigned long long inlen)
{
    init();
    update(in, inlen);
    final(out);

    return Hash_Result::SUCCES_HASH;
}



