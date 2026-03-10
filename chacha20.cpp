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
        state[i + 13] = load32le(&nonce[i * 4]);
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

void ChaCha20::quarterCore(uint32_t* output) {
    uint32_t x32[16];

    for (int i = 0; i < 16; i++) {
        x32[i] = state[i];
    }

    for (int i = 0; i < 10; i++) {
        quarterRound(x32[0], x32[4], x32[8], x32[12]);
        quarterRound(x32[1], x32[5], x32[9], x32[13]);
        quarterRound(x32[2], x32[6], x32[10], x32[14]);
        quarterRound(x32[3], x32[7], x32[11], x32[15]);
    
        quarterRound(x32[0], x32[5], x32[10], x32[15]);
        quarterRound(x32[1], x32[6], x32[11], x32[12]);
        quarterRound(x32[2], x32[7], x32[8], x32[13]);
        quarterRound(x32[3], x32[4], x32[9], x32[14]);
    }

    for (int i = 0; i < 16; i++) {
        output[i] = x32[i] + state[i];
    }
}

void ChaCha20::crypto(uint8_t* input, int len) {
    uint32_t keyStream[16];
    uint8_t* keyStreamBytes = reinterpret_cast<uint8_t*>(keyStream);

    for (int i = 0; i < len; i += 64) {
        quarterCore(keyStream);

        for (int j = 0; j < 64 && len > (i + j); j++) {
            input[i + j] = input[i + j] ^ keyStreamBytes[j];
        }

        state[12]++;
    }
}