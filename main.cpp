#include <iostream>
#include <random>
#include "chacha20.h"
#include <fstream>
#include <chrono>

template<bool with_logs>
void encrypt_file(ChaCha20& ch) {
    std::cout << "enter path #: ";
    std::string path;
    std::cin >> path;

    std::ifstream in { path, std::ios::binary };
    std::ofstream out (path + ".enc", std::ios::binary );
    in.seekg(0, std::ios::end);
    size_t file_size = in.tellg();
    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(256 * 1024 * 1024);
    
    double total_bytes_hand;
    std::chrono::duration<double> total_encrypted_time;
    if constexpr (with_logs) {
        total_bytes_hand = 0;
        total_encrypted_time = std::chrono::duration<double>::zero();
    }
    std::chrono::high_resolution_clock::time_point start_encrypted;

    while (in.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || in.gcount() > 0) {
        if constexpr (with_logs) {
            start_encrypted = std::chrono::high_resolution_clock::now();
        }
        ch.crypto(buffer.data(), in.gcount());
        
        if constexpr (with_logs) {
            auto end = std::chrono::high_resolution_clock::now();
            total_encrypted_time += (end - start_encrypted);
            total_bytes_hand += in.gcount();
        }

        out.write(reinterpret_cast<char*>(buffer.data()), in.gcount());
    }

    std::cout << "Speed (MB/s): " << (total_bytes_hand / (1024 * 1024)) / total_encrypted_time.count();
}

int main() {
    ChaCha20 ch;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    uint8_t key[32];
    uint8_t nonce[12];

    for (int i = 0; i < 32; i++) 
        key[i] = static_cast<uint8_t>(dis(gen));


    for (int i = 0; i < 12; i++)
        nonce[i] = static_cast<uint8_t>(dis(gen));
    
    
    ch.init(key, nonce);

    encrypt_file<true>(ch);
}