#ifndef CHACHA_20
#define CHACHA_20

#include <cstdint>
#include <array>
#include <immintrin.h>

class ChaCha20 {
public:
    std::array<uint32_t, 16> state;

    void init(uint8_t key[32], uint8_t nonce[12]);
    __m256i rot32l(__m256i x, int n);
    void quarterRound(__m256i& a, __m256i& b, __m256i& c, __m256i& d);
    uint32_t load32le(uint8_t *key);
    void quarterCore(uint32_t* output);
    void crypto(uint8_t* input, int len);
};

#endif