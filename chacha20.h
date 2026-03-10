#ifndef CHACHA_20
#define CHACHA_20

#include <cstdint>
#include <array>

class ChaCha20 {
public:
    std::array<uint32_t, 16> state;

    void init(uint8_t key[32], uint8_t nonce[12]);
    uint32_t rot32l(uint32_t x, int n);
    void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
    uint32_t load32le(uint8_t *key);
    void quarterCore(uint32_t* output);
    void crypto(uint8_t* input, int len);
};

#endif