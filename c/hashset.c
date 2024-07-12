#include "hashset.h"
#include <stdlib.h>
#include "xxhash.h"

// define hashset size
#define HASHSET_SIZE 284167840

typedef struct Node {
    uint64_t hash;
    struct Node* next;
} Node;

struct HashSet {
    Node* buckets[HASHSET_SIZE];
};

uint64_t hash(char key[20]) {
    return XXH64(&key, sizeof(uint64_t), 0);
}

HashSet* createHashSet() {
    HashSet* set = (HashSet*)malloc(sizeof(HashSet));
    if (set == NULL) {
        // handle malloc failure
        return NULL;
    }
    for (int i = 0; i < HASHSET_SIZE; ++i)
        set->buckets[i] = NULL;
    return set;
}

void addToHashSet(HashSet* set, uint64_t hash) {
    if (set == NULL) return;
    uint64_t index = hash % HASHSET_SIZE;
    Node* newNode = (Node*)malloc(sizeof(Node));
    if (newNode == NULL) {
        // handle malloc failure
        return;
    }
    newNode->hash = hash;
    newNode->next = set->buckets[index];
    set->buckets[index] = newNode;
}

bool contains(HashSet* set, uint64_t hash) {
    if (set == NULL) return false;
    uint64_t index = hash % HASHSET_SIZE;
    Node* current = set->buckets[index];
    while (current != NULL) {
        if (current->hash == hash)
            return true;
        current = current->next;
    }
    return false;
}

