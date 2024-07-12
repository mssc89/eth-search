#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <omp.h>

#include "secp256k1.h"
#include "sha3.h"
#include "xxhash.h"
#include "hashset.h"

// number of threads to be used
#define NUM_THREADS 48

// define total number of keys to check
#define NUM_KEYS 536870928

// function to increment a binary string by one
void incrementPrivateKey(unsigned char privateKeyBytes[32]) {
    int i;
    bool carry = true;
    
    for (i = 31; i >= 0 && carry; i--) {
        if (privateKeyBytes[i] == 0xFF) {
            privateKeyBytes[i] = 0x00;
        } else {
            privateKeyBytes[i]++;
            carry = false;
        }
    }
}

// function to set a private key to a specific value
void setPrivateKey(unsigned char privateKeyBytes[32], unsigned long long number) {
    unsigned char carry = 0;
    int i;
    
    // Increment bytes of privateKeyBytes with corresponding bytes of number
    for (i = 31; i >= 0; i--) {
        unsigned long long sum = privateKeyBytes[i] + (number & 0xFF) + carry;
        privateKeyBytes[i] = sum & 0xFF; // Store only the least significant byte
        carry = (sum >> 8) & 0xFF; // Carry-over to the next byte
        number >>= 8; // Move to the next byte of the number
    }
}

// function to be executed by each thread
void generateAddress(unsigned int thread_id, unsigned long long keysPerThread, HashSet *set) {
    printf("Thread %d is running\nChecking range %llu to %llu\n", thread_id, thread_id * keysPerThread + 1, (thread_id + 1) * keysPerThread);
    
    secp256k1_context *ctx = NULL;
    unsigned char privateKeyBytes[32] = {0}; // initialize private key to 0
    unsigned char public_key64[65];
    size_t pk_len = 65;
    sha3_context c;
    uint8_t *hash = NULL;
    char address[40];
    
    sha3_Init256(&c);
    sha3_SetFlags(&c, SHA3_FLAGS_KECCAK);
    
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    setPrivateKey(privateKeyBytes, thread_id * keysPerThread);

    // run through the range of keys
    for(unsigned long long key = 0; key < keysPerThread; key++){
        incrementPrivateKey(privateKeyBytes);
        
        secp256k1_pubkey pubkey;
        if(secp256k1_ec_pubkey_create(ctx, &pubkey, privateKeyBytes) == 0){
            printf("Error generating public key\n");
        }
        
        secp256k1_ec_pubkey_serialize(ctx, public_key64, &pk_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        
        // Shift elements one position to the left
        for (int i = 0; i < 64; i++) {
            public_key64[i] = public_key64[i + 1];
        }
        
        sha3_Init256(&c);
        sha3_SetFlags(&c, SHA3_FLAGS_KECCAK);
        sha3_Update(&c, public_key64, 64);
        hash = (uint8_t *)sha3_Finalize(&c);

        // convert hash to address (last 20 chars)
        for (int i = 12; i < 32; i++) {
            sprintf(&address[(i-12) * 2], "%02x", hash[i]);
        }

        if (contains(set, XXH64(address, sizeof(address), 0))) {
            printf("Address %s already exists in the set\n", address);
        }
    }
}

int main() {
    struct timespec start, end;
    double elapsed_time;

    //determine number of keys per thread
    unsigned long long keysPerThread = NUM_KEYS / NUM_THREADS;

    printf("Keys per thread: %llu\n", keysPerThread);

    HashSet* set = createHashSet();

    // Check if set is created successfully
    if (set == NULL) {
        printf("Failed to create HashSet\n");
        return 1;
    }

    FILE *file;
    char line[64];
    uint64_t value;

    // open file with known addresses
    file = fopen("addresses.csv", "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    // read file line by line
    while (fgets(line, sizeof(line), file)) {
        // convert line to uint64_t
        value = strtoull(line, NULL, 10);

        // add value to hash set
        addToHashSet(set, value);
    }

    // close file
    fclose(file);

    printf("File loaded\n");

    // start measuring time
    clock_gettime(CLOCK_MONOTONIC, &start);

    #pragma omp parallel num_threads(NUM_THREADS)
    {
        generateAddress(omp_get_thread_num(), keysPerThread, set);
    }

    #pragma omp barrier

    // end measuring time
    clock_gettime(CLOCK_MONOTONIC, &end);

    // calculate the elapsed time
    elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("Time taken: %f seconds\n", elapsed_time);

    double runsPerSecond = 536870760 / elapsed_time;
    printf("Runs per second: %f", runsPerSecond);
    
    return 0;
}	

