#include "ChaCha20.h"

void ChaCha20::init(uint8_t key[32], uint8_t nonce[12]) {
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    for (int i = 0; i < 8; i++) {
        state[i + 4] = load32le(&key[i * 4]);
    }

    state[12] = 0;

    for (int i = 0; i < 3; i++)
        state[i] = load32le(&nonce[i * 4]);
}

uint32_t ChaCha20::load32le(uint8_t* key) {
    return (
        key[0] |
        key[1] << 8 |
        key[2] << 16 |
        key[3] << 24
    );
}

uint32_t ChaCha20::rot32l(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

void ChaCha20::quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rot32l(d, 16);
    c += d; b ^= c; b = rot32l(b, 12);
    a += b; d ^= a; d = rot32l(d, 8);
    c += d; b ^= c; b = rot32l(b, 7);
}