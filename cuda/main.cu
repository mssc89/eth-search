#include <iostream>
#include <cmath>
#include <cstddef>
#include <limits>
#include <fstream>
#include <sstream>
#include <cstdint>
#include <cinttypes>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <cuda_runtime.h>
#include <cuda/atomic>
#include <cuco/extent.cuh>
#include <cuco/detail/hash_functions/xxhash.cuh>
#include <cuco/static_set.cuh>
#include <thrust/device_vector.h>
#include <thrust/host_vector.h>
#include <thrust/functional.h>
#include <thrust/logical.h>
#include <thrust/sequence.h>
#include <cooperative_groups.h>

#include "./secp256k1/inc_vendor.h"
#include "./secp256k1/inc_types.h"
#include "./secp256k1/inc_ecc_secp256k1.h"
#include "./secp256k1/inc_ecc_secp256k1.cl"

#include "./keccak/keccak256.h"
#include "./keccak/keccak256.cl"

// little endian to big endian
__device__ u32 le_to_be(u32 x)
{
    return ((x & 0xFF) << 24) | (((x >> 8) & 0xFF) << 16) | (((x >> 16) & 0xFF) << 8) | ((x >> 24) & 0xFF);
}

// get keccak256 hash in big endian
__device__ void keccak256_get_hash_be(u32* r, const u8* msg, const u32 len)
{
    u64 state[25] = {};
    keccak256_update_state(state, (u8*)msg, len);

    r[0] = le_to_be((u32)(state[1] >> 32));
    r[1] = le_to_be((u32)state[2]);
    r[2] = le_to_be((u32)(state[2] >> 32));
    r[3] = le_to_be((u32)state[3]);
    r[4] = le_to_be((u32)(state[3] >> 32));
}

// convert u32 to hexadecimal
__device__ void u32_to_hex(std::byte* result, u32* k, size_t len){
    for (size_t i = 0; i < len; ++i) {
        uint32_t value = (uint32_t)k[i];
        for (int j = 0; j < 8; ++j) {
            int nibble = (value >> (28 - j * 4)) & 0xF;
            result[i * 8 + j] = std::byte((nibble < 10) ? ('0' + nibble) : ('a' + nibble - 10));
        }
    }
}

// secp256k1 g point
__constant__ secp256k1_t g = {
    0x16f81798, 0x59f2815b, 0x2dce28d9, 0x029bfcdb,
    0xce870b07, 0x55a06295, 0xf9dcbbac, 0x79be667e,
    0xfb10d4b8, 0x9c47d08f, 0xa6855419, 0xfd17b448,
    0x0e1108a8, 0x5da4fbfc, 0x26a3c465, 0x483ada77,
    0x04ef2777, 0x63b82f6f, 0x597aabe6, 0x02e84bb7,
    0xf1eef757, 0xa25b0403, 0xd95c3b9a, 0xb7c52588,
    0xbce036f9, 0x8601f113, 0x836f99b0, 0xb531c845,
    0xf89d5229, 0x49344f85, 0x9258c310, 0xf9308a01,
    0x84b8e672, 0x6cb9fd75, 0x34c2231b, 0x6500a999,
    0x2a37f356, 0x0fe337e6, 0x632de814, 0x388f7b0f,
    0x7b4715bd, 0x93460289, 0xcb3ddce4, 0x9aff5666,
    0xd5c80ca9, 0xf01cc819, 0x9cd217eb, 0xc77084f0,
    0xb240efe4, 0xcba8d569, 0xdc619ab7, 0xe88b84bd,
    0x0a5c5128, 0x55b4a725, 0x1a072093, 0x2f8bde4d,
    0xa6ac62d6, 0xdca87d3a, 0xab0d6840, 0xf788271b,
    0xa6c9c426, 0xd4dba9dd, 0x36e5e3d6, 0xd8ac2226,
    0x59539959, 0x235782c4, 0x54f297bf, 0x0877d8e4,
    0x59363bd9, 0x2b245622, 0xc91a1c29, 0x2753ddd9,
    0xcac4f9bc, 0xe92bdded, 0x0330e39c, 0x3d419b7e,
    0xf2ea7a0e, 0xa398f365, 0x6e5db4ea, 0x5cbdf064,
    0x087264da, 0xa5082628, 0x13fde7b5, 0xa813d0b8,
    0x861a54db, 0xa3178d6d, 0xba255960, 0x6aebca40,
    0xf78d9755, 0x5af7d9d6, 0xec02184a, 0x57ec2f47,
    0x79e5ab24, 0x5ce87292, 0x45daa69f, 0x951435bf
};

// xxHash64 hasher
__shared__ cuco::detail::XXHash_64<char> hasher;

// main kernel
template <typename SetRef>
__global__ void genEthAddressSeq(SetRef set, u32 *host_count)
{
    // generated address
    u32 r[5];

    // private key
    u32 k[8];

    // secp256k1 result coordinates
    u32 x[8];
    u32 y[8];

    // keccak256 input
    u32 w[16];

    // get first element of private key
    k[0] = blockIdx.x * blockDim.x + threadIdx.x;

    // set the rest of private key
    for(int i=1; i < 8; i++){
        k[i] = host_count[i-1];
    }

    // run secp256k1
    point_mul_xy(x, y, k, &g);

    // convert coordinates to big endian
    for (int i = 0; i < 8; ++i) {
        w[i] = le_to_be(x[7 - i]);
        w[i + 8] = le_to_be(y[7 - i]);
    }

    // run keccak256
    keccak256_get_hash_be(r, (u8 *)w, 64);

    // convert to hexadecimal
    std::byte result[40];
    u32_to_hex(result, r, 5);

    // calculate xxHash
    std::uint64_t outhash = hasher.compute_hash(result, cuco::extent<std::size_t, 40>{});

    // search for address in set
    auto tile = cooperative_groups::tiled_partition<SetRef::cg_size>(cooperative_groups::this_thread_block());

    tile.sync();

    if (set.contains(tile, outhash) && tile.thread_rank() == 0) {
        printf("!!! Found collision !!!:\n%u, %u, %u, %u, %u, %u, %u, %u | %u, %u, %u, %u, %u\nAddress: %s\nxxHash (dec): %lu\n", (unsigned int)k[7], (unsigned int)k[6], (unsigned int)k[5], (unsigned int)k[4], (unsigned int)k[3], (unsigned int)k[2], (unsigned int)k[1], (unsigned int)k[0], (unsigned int)r[0], (unsigned int)r[1], (unsigned int)r[2], (unsigned int)r[3], (unsigned int)r[4], result, outhash);
    }
}

void incrementWithRollover(u32* number) {
    for (int i = 0; i < 7; i++) {
        number[i]++;

        if (number[i] != 0) {
            break;
        }
    }
}

int main(void) {
    std::cout << "Loading known addresses..." << std::endl;

    using Key = uint64_t;

    // empty slots are represented by reserved "sentinel" values. These values should be selected such that they never occur in input data
    Key constexpr empty_key_sentinel = 0;
  
    // number of keys to be inserted
    std::size_t constexpr num_keys = 277699467;
  
    // compute capacity based on a 50% load factor
    auto constexpr load_factor = 0.5;
    std::size_t const capacity = std::ceil(num_keys / load_factor);
  
    // constructs a set with at least `capacity` slots using 0 as the empty keys sentinel.
    cuco::static_set<Key> set{capacity, cuco::empty_key{empty_key_sentinel}};

    thrust::host_vector<Key> keys_host(num_keys);
  
    std::ifstream inputFile("known_addresses_hashed.csv");
    if (!inputFile.is_open()) {
        std::cerr << "Error opening file!" << std::endl;
        return 1;
    }
  
    uint64_t currentNumber;
    double lastProgress = 0.0;
  
    // load keys and output progress
    for (std::size_t i = 0; i < num_keys; ++i) {
      inputFile >> currentNumber;
      keys_host[i] = currentNumber;

      double progress = static_cast<double>(i) / num_keys * 100.0;

      if (progress - lastProgress >= 1.0) {
        std::cout << "Loading progress: " << progress << "%" << std::endl;
        lastProgress = progress;
      }
    }
  
    inputFile.close();
  
    thrust::device_vector<Key> keys = keys_host;

    // insert all keys into the hash set
    set.insert(keys.begin(), keys.end());

    std::cout << "Done loading known addresses" << std::endl << "First 5 addresses (xxhash64):" << std::endl;

    //print first 5 addresses
    for (std::size_t i = 0; i < 5; ++i) {
        std::cout << keys[i] << std::endl;
    }

    // number of "blocks" to be generated
    // each block is 4294967296 addresses
    int numBlocks = 10;

    cudaSetDevice(0);

    // starter key (0)
    u32 hostArray[7] = {0,0,0,0,0,0,0};
    u32 *deviceArray;

    // allocate memory on the GPU
    cudaMalloc(&deviceArray, 7 * sizeof(u32));

    // generation loop
    for (int i = 0; i < numBlocks; i++) {
        // create events for timing
        cudaEvent_t start, stop;
        cudaEventCreate(&start);
        cudaEventCreate(&stop);
        cudaEventRecord(start);

        // copy starter key to GPU
        cudaMemcpy(deviceArray, hostArray, 7 * sizeof(u32), cudaMemcpyHostToDevice);
            
        // run kernel
        genEthAddressSeq<<<8388608, 512>>>(set.ref(cuco::contains), deviceArray);
        
        // synchronize and check for errors
        cudaDeviceSynchronize();
        cudaError_t err = cudaGetLastError();

        if(err != cudaSuccess)
        {
            std::cout << "CUDA Error: " << cudaGetErrorString(err);
        }

        // copy result (last key) back to CPU
        cudaMemcpy(hostArray, deviceArray, 7 * sizeof(u32), cudaMemcpyDeviceToHost);

        // output the result (last key)
        std::cout << "Result: ";
        for (int j = 0; j < 7; ++j) {
            std::cout << hostArray[j] << " ";
        }
        std::cout << std::endl;

        // increment the key
        incrementWithRollover(hostArray);

        // stop timing
        cudaEventRecord(stop);
        cudaEventSynchronize(stop);

        // calculate time
        float milliseconds = 0;
        cudaEventElapsedTime(&milliseconds, start, stop);

        // Calculate runs per second
        unsigned long long int totalRuns = 0xFFFFFFFF;
        unsigned long long int runsPerSecond = totalRuns / (milliseconds / 1000.0f);
        printf("miliseconds: %f\n", milliseconds);
        printf("number of runs: %llu\n", totalRuns);
        printf("Number of runs per second: %.2f Mh/s\n", runsPerSecond / 1e6);
        printf("Number of runs per second: %llu h/s\n", runsPerSecond);

        cudaEventDestroy(start);
        cudaEventDestroy(stop);
    }

    return 0;
}

