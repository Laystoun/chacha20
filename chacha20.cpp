#include "ChaCha20.h"
#include <immintrin.h>

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

__m256i ChaCha20::rot32l(__m256i x, int n) {
    return _mm256_or_si256(
        _mm256_slli_epi32(x, n),
        _mm256_srli_epi32(x, 32 - n)
    );
}

void ChaCha20::quarterRound(__m256i& a, __m256i& b, __m256i& c, __m256i& d) {
    a = _mm256_add_epi32(a, b); d = _mm256_xor_si256(d, a); d = rot32l(d, 16);
    c = _mm256_add_epi32(c, d); b = _mm256_xor_si256(b, c); b = rot32l(b, 12);
    a = _mm256_add_epi32(a, b); d = _mm256_xor_si256(d, a); d = rot32l(d, 8);
    c = _mm256_add_epi32(c, d); b = _mm256_xor_si256(b, c); b = rot32l(b, 7);
}

void ChaCha20::quarterCore(uint32_t* keyStream) {
    __m256i v0 = _mm256_set_m128i(_mm_loadu_si128((__m128i*)&state[0]), _mm_loadu_si128((__m128i*)&state[0]));
    __m256i v1 = _mm256_set_m128i(_mm_loadu_si128((__m128i*)&state[4]), _mm_loadu_si128((__m128i*)&state[4]));
    __m256i v2 = _mm256_set_m128i(_mm_loadu_si128((__m128i*)&state[8]), _mm_loadu_si128((__m128i*)&state[8]));


    __m256i v3 = _mm256_setr_epi32(
        state[12], state[13], state[14], state[15],
        state[12] + 1, state[13], state[14], state[15]
    );

    __m256i a = v0, b = v1, c = v2, d = v3;

    for (int i = 0; i < 10; i++) {
        quarterRound(a, b, c, d);

        b = _mm256_shuffle_epi32(b, _MM_SHUFFLE(0, 3, 2, 1));
        c = _mm256_shuffle_epi32(c, _MM_SHUFFLE(1, 0, 3, 2));
        d = _mm256_shuffle_epi32(d, _MM_SHUFFLE(2, 1, 0, 3));

        quarterRound(a, b, c, d);

        b = _mm256_shuffle_epi32(b, _MM_SHUFFLE(2, 1, 0, 3)); 
        c = _mm256_shuffle_epi32(c, _MM_SHUFFLE(1, 0, 3, 2)); 
        d = _mm256_shuffle_epi32(d, _MM_SHUFFLE(0, 3, 2, 1));
    }

    state[12] += 2;

    a = _mm256_add_epi32(a, v0); b =_mm256_add_epi32(b, v1);
    c = _mm256_add_epi32(c, v2); d = _mm256_add_epi32(d, v3);

    _mm_storeu_si128((__m128i*)&keyStream[0], _mm256_castsi256_si128(a));
    _mm_storeu_si128((__m128i*)&keyStream[4], _mm256_castsi256_si128(b));
    _mm_storeu_si128((__m128i*)&keyStream[8], _mm256_castsi256_si128(c));
    _mm_storeu_si128((__m128i*)&keyStream[12], _mm256_castsi256_si128(d));    

    _mm_storeu_si128((__m128i*)&keyStream[16], _mm256_extracti128_si256(a, 1));
    _mm_storeu_si128((__m128i*)&keyStream[20], _mm256_extracti128_si256(b, 1));
    _mm_storeu_si128((__m128i*)&keyStream[24], _mm256_extracti128_si256(c, 1));
    _mm_storeu_si128((__m128i*)&keyStream[28], _mm256_extracti128_si256(d, 1));
}

void ChaCha20::crypto(uint8_t* input, int len) {
    uint32_t keyStream[32];

    int i = 0;
    for (;i < (len - 128); i += 128) {
        quarterCore(keyStream);

        for (int x = 0; x < 4; x++) {
            __m256i key_load = _mm256_loadu_si256((__m256i*)&keyStream[x * 8]);
            __m256i data = _mm256_loadu_si256((__m256i*)&input[i + x * 32]);
            __m256i res = _mm256_xor_si256(key_load, data);
            _mm256_storeu_si256((__m256i*)&input[i + x * 32], res);
        }
    }

    if (i < len) {
        quarterCore(keyStream);

        uint8_t* key_b = reinterpret_cast<uint8_t*>(keyStream);
        for (int j = 0; i + j < len; j++) {
            input[i + j] ^= key_b[j];
        } 
    }
}