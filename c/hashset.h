#ifndef HASHSET_H
#define HASHSET_H

#include <stdint.h>
#include <stdbool.h>

// Define your HashSet structure
typedef struct HashSet HashSet;

// Function declarations
HashSet* createHashSet();
void addToHashSet(HashSet* set, uint64_t hash);
bool contains(HashSet* set, uint64_t hash);

// Declaration for the hash function
uint64_t hash(char key[20]);

#endif /* HASHSET_H */
