#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <limits.h>
#include "hash_functions.h"

#define HASH_BYTES 16  // Only the first 16 bytes of a hash are kept


// Structure for storing each found or not ofund password.
struct found_password {
    char target_hash[2 * HASH_BYTES + 1];
    char *password;       // Matching candidate password (if found)
    char *algorithm;      // Which hash algorithm produced the match
    int candidate_index;  // Lower index means an earlier candidate (better match)
};

// Define a type for the hash functions (they return a binary hash).
typedef unsigned char *(*hashing_function)(unsigned char *, unsigned int);


// Global list of hash functions and their names.
int num_algorithms = 4;
hashing_function hash_funcs[4] = { calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512 };
char *algorithm_names[4] = { "MD5", "SHA1", "SHA256", "SHA512" };

//Compare two hexadecimal hash strings; returns 1 if they are identical
static inline int are_hashes_equal(const char *hash1, const char *hash2) {
    for (int i = 0; i < 2 * HASH_BYTES; i++) {
        if (hash1[i] != hash2[i])
            return 0;
    }
    return 1;
}


//Simple password map (hash map) implementation
struct password_map_entry {
    char key[2 * HASH_BYTES + 1];  // The target hash as a hex string
    int found_index;               // Index into the found_password array
    struct password_map_entry *next; // Pointer for handling collisions (chaining)
};

// djb2 hash function (converts a string into an unsigned long hash).
unsigned long djb2_hash(const char *str) {
    unsigned long hash = 5381;
    int character;
    while ((character = *str++))
        hash = ((hash << 5) + hash) + character; // hash * 33 + character
    return hash;
}


// Structure to pass parameters to each thread.
typedef struct {
    int num_candidates;                   // Total number of candidate passwords
    int num_target_hashes;                // Total number of hashed passwords
    char **candidate_passwords;           // Array of candidate password strings
    struct found_password *found_list;    // Array of target hash entries to update
    pthread_mutex_t *entry_mutexes;       // One mutex per found password entry

    // Static partitioning parameters:
    int thread_id;                        // This thread's ID 
    int total_threads;                    // Total number of worker threads

    // Parameters for the password map (hash map):
    struct password_map_entry **password_map; // Array of map buckets
    int map_size;                         // Number of buckets in the map
} thread_args;


// The result is stored in the provided 'hex_string' buffer.
static inline void convert_to_hex(const unsigned char *binary, char *hex_string) {
    static const char hex_digits[] = "0123456789abcdef";
    for (int i = 0; i < HASH_BYTES; i++) {
        hex_string[2 * i]     = hex_digits[binary[i] >> 4];
        hex_string[2 * i + 1] = hex_digits[binary[i] & 0x0f];
    }
    hex_string[2 * HASH_BYTES] = '\0';
}


// Each thread works on every total_threads-th candidate based on its thread_id.
void *process_candidates(void *arg) {
    thread_args *args = (thread_args *) arg;
    int totalCandidates = args->num_candidates;
    int myId = args->thread_id;

    // Loop over candidate passwords assigned to this thread.
    for (int candidateIndex = myId; candidateIndex < totalCandidates; candidateIndex += args->total_threads) {
        char *currentPassword = args->candidate_passwords[candidateIndex];
        int passwordLength = (int)strlen(currentPassword); // Cache the password length

        // Try each available hash algorithm.
        for (int algo = 0; algo < num_algorithms; algo++) {
            // Compute the binary hash for the current candidate.
            unsigned char *binaryHash = hash_funcs[algo]((unsigned char *)currentPassword, passwordLength);
            char computedHex[2 * HASH_BYTES + 1];
            convert_to_hex(binaryHash, computedHex);
            free(binaryHash);

            // Look up the computed hash in our password map.
            unsigned long hashValue = djb2_hash(computedHex);
            int bucketIndex = hashValue % args->map_size;
            struct password_map_entry *entry = args->password_map[bucketIndex];

            // Check all entries in this bucket (handle collisions).
            while (entry) {
                if (strcmp(entry->key, computedHex) == 0) {
                    int foundIdx = entry->found_index;
                    // Lock the specific found password entry before updating.
                    pthread_mutex_lock(&args->entry_mutexes[foundIdx]);
                    // Update the entry if no match has been recorded or if this candidate comes earlier.
                    if (args->found_list[foundIdx].password == NULL ||
                        candidateIndex < args->found_list[foundIdx].candidate_index) {
                        if (args->found_list[foundIdx].password) {
                            free(args->found_list[foundIdx].password);
                        }
                        args->found_list[foundIdx].password = strdup(currentPassword);
                        args->found_list[foundIdx].algorithm = algorithm_names[algo];
                        args->found_list[foundIdx].candidate_index = candidateIndex;
                    }
                    pthread_mutex_unlock(&args->entry_mutexes[foundIdx]);
                }
                entry = entry->next;
            }
        }
    }
    return NULL;
}


// Main function that reads input files, spawns threads to process candidate passwords, and writes the results to the output file
void crack_hashed_passwords(char *candidate_file, char *hashed_file, char *output_file) {
    FILE *file;
    char tempBuffer[256];  // Temporary buffer for reading candidate passwords
    char tempHash[2 * HASH_BYTES + 1];

   
    int totalTargetHashes = 0;
    struct found_password *foundPasswords;

    file = fopen(hashed_file, "r");
    assert(file != NULL);
    // Count how many hashed passwords we have.
    while (fscanf(file, "%s", tempHash) == 1)
        totalTargetHashes++;
    rewind(file);

    // Allocate array for the found passwords.
    foundPasswords = malloc(totalTargetHashes * sizeof(struct found_password));
    assert(foundPasswords != NULL);
    for (int i = 0; i < totalTargetHashes; i++) {
        fscanf(file, "%s", foundPasswords[i].target_hash);
        foundPasswords[i].password = NULL;
        foundPasswords[i].algorithm = NULL;
        foundPasswords[i].candidate_index = INT_MAX;
    }
    fclose(file);

   
    // Set map size to 2*totalTargetHashes + 1 for a low load factor
    int mapSize = 2 * totalTargetHashes + 1;
    struct password_map_entry **passwordMap = malloc(mapSize * sizeof(struct password_map_entry *));
    assert(passwordMap != NULL);
    for (int i = 0; i < mapSize; i++)
        passwordMap[i] = NULL;

    // Insert each target hash into the map
    for (int i = 0; i < totalTargetHashes; i++) {
        struct password_map_entry *newEntry = malloc(sizeof(struct password_map_entry));
        assert(newEntry != NULL);
        strcpy(newEntry->key, foundPasswords[i].target_hash);
        newEntry->found_index = i;
        unsigned long keyHash = djb2_hash(newEntry->key);
        int bucket = keyHash % mapSize;
        newEntry->next = passwordMap[bucket];
        passwordMap[bucket] = newEntry;
    }

    //Read Candidate Passwords 
    int totalCandidates = 0;
    file = fopen(candidate_file, "r");
    assert(file != NULL);
    while (fscanf(file, "%s", tempBuffer) == 1)
        totalCandidates++;
    rewind(file);

    char **candidatePasswords = malloc(totalCandidates * sizeof(char *));
    assert(candidatePasswords != NULL);
    int candidateIndex = 0;
    while (fscanf(file, "%s", tempBuffer) == 1) {
        candidatePasswords[candidateIndex++] = strdup(tempBuffer);
    }
    fclose(file);

    //Initialize Mutexes 
    pthread_mutex_t *mutexes = malloc(totalTargetHashes * sizeof(pthread_mutex_t));
    for (int i = 0; i < totalTargetHashes; i++) {
        pthread_mutex_init(&mutexes[i], NULL);
    }

    
    // We use static partitioning. 
    int totalThreads = 6;  // Adjust this based on available CPU cores.
    pthread_t threads[totalThreads];
    thread_args threadParameters[totalThreads];
    for (int i = 0; i < totalThreads; i++) {
        threadParameters[i].num_candidates = totalCandidates;
        threadParameters[i].num_target_hashes = totalTargetHashes;
        threadParameters[i].candidate_passwords = candidatePasswords;
        threadParameters[i].found_list = foundPasswords;
        threadParameters[i].entry_mutexes = mutexes;
        threadParameters[i].thread_id = i;
        threadParameters[i].total_threads = totalThreads;
        threadParameters[i].password_map = passwordMap;
        threadParameters[i].map_size = mapSize;
        pthread_create(&threads[i], NULL, process_candidates, &threadParameters[i]);
    }
    for (int i = 0; i < totalThreads; i++) {
        pthread_join(threads[i], NULL);
    }

    //Write the Output
    file = fopen(output_file, "w");
    assert(file != NULL);
    for (int i = 0; i < totalTargetHashes; i++) {
        if (foundPasswords[i].password == NULL)
            fprintf(file, "not found\n");
        else
            fprintf(file, "%s:%s\n", foundPasswords[i].password, foundPasswords[i].algorithm);
    }
    fclose(file);

    //Cleanup Memory 
    for (int i = 0; i < totalTargetHashes; i++) {
        pthread_mutex_destroy(&mutexes[i]);
        free(foundPasswords[i].password);
    }
    free(mutexes);
    free(foundPasswords);
    for (int i = 0; i < totalCandidates; i++) {
        free(candidatePasswords[i]);
    }
    free(candidatePasswords);
    for (int i = 0; i < mapSize; i++) {
        struct password_map_entry *entry = passwordMap[i];
        while (entry) {
            struct password_map_entry *nextEntry = entry->next;
            free(entry);
            entry = nextEntry;
        }
    }
    free(passwordMap);
}
