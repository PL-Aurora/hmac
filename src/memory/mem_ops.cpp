#include "../inc/memory/mem_ops.h"

void xor_bytes(uint8_t* buff_out, const uint8_t* buff_in1, const uint8_t* buff_in2, const std::size_t buff_size){
    uint64_t* b_o = reinterpret_cast<uint64_t*>(buff_out);
    const uint64_t* b_i1 = reinterpret_cast<const uint64_t*>(buff_in1);
    const uint64_t* b_i2 = reinterpret_cast<const uint64_t*>(buff_in2);
    std::size_t blocks = buff_size / sizeof(uint64_t);
    
    for(std::size_t i = 0; i < blocks; i++)
        b_o[i] = b_i1[i] ^ b_i2[i];
    
    for(std::size_t i = blocks * sizeof(uint64_t); i < buff_size; i++)
        buff_out[i] = buff_in1[i] ^ buff_in2[i];
}
