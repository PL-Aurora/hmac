#ifndef LIBCRYPTO_MEM_OPS_H
#define LIBCRYPTO_MEM_OPS_H

#include <cstdint>
#include <algorithm>

void xor_bytes(uint8_t* buff_out, const uint8_t* buff_in1, const uint8_t* buff_in2, const std::size_t buff_size);

/**
 * Template Funkcji zerującej wskazany obszar pamięci
 *  @param ptr wskażnik początku obszaru pamięci,
 *  @param n – rozmiar (liczba elementów typu T)
 */
#pragma GCC push_options
#pragma GCC optimize ("O0")
template<typename Tp>
inline void  __attribute__((optimize("O0"))) zeroize(volatile Tp* ptr, const std::size_t n){
	  std::fill_n(ptr, n, 0);
}
#pragma GCC pop_options


// #pragma GCC push_options
// #pragma GCC optimize ("O0")
// template<typename Tp>
// inline void  __attribute__((optimize("O0"))) zeroize(volatile Tp* p, std::size_t n){
// 	  std::memset(reinterpret_cast<void*>(p), 0, sizeof(Tp)*n);
// }
// #pragma GCC pop_options

#endif // LIBCRYPTO_MEM_OPS_H