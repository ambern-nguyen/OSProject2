#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <limits.h>
#include "hash_functions.h"

#define KEEP 16 // only the first 16 bytes of a hash are kept

// Structure for storing each hashed password.
struct cracked_hash {
    char hash[2 * KEEP + 1];
    char *password;
    char *alg;
    int candidate_index;  // lower index means an earlier candidate
};

typedef unsigned char *(*hashing)(unsigned char *, unsigned int);

int n_algs = 4;
hashing fn[4] = { calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512 };
char *algs[4] = { "MD5", "SHA1", "SHA256", "SHA512" };

// Compare two hexadecimal hash strings; returns 1 if identical.
int compare_hashes(char *a, char *b) {
    for (int i = 0; i < 2 * KEEP; i++) {
        if (a[i] != b[i])
            return 0;
    }
    return 1;
}

// Thread argument structure using a shared counter (pointer to int)
typedef struct {
    int n_candidates;            // total number of candidate passwords
    int n_hashed;                // number of hashed entries
    char **candidates;           // candidate password array
    struct cracked_hash *cracked_hashes; // array of hashed passwords
    pthread_mutex_t *mutexes;    // one mutex per cracked_hash entry
    int *next_candidate;         // pointer to a shared counter for dynamic scheduling
} thread_arg;

// Modified thread function using dynamic scheduling with __sync_fetch_and_add.
void *thread_crack(void *arg) {
    thread_arg *targ = (thread_arg *) arg;
    int i;
    while (1) {
        // Atomically fetch and increment the shared counter.
        i = __sync_fetch_and_add(targ->next_candidate, 1);
        if (i >= targ->n_candidates)
            break;
        char *password = targ->candidates[i];
        // For each algorithm, compute the hash and compare against each stored hash.
        for (int k = 0; k < n_algs; k++) {
            unsigned char *hash = fn[k]((unsigned char *)password, strlen(password));
            char hex_hash[2 * KEEP + 1];
            for (int j = 0; j < KEEP; j++)
                sprintf(&hex_hash[2 * j], "%02x", hash[j]);
            hex_hash[2 * KEEP] = '\0';
            free(hash);
            for (int j = 0; j < targ->n_hashed; j++) {
                if (compare_hashes(hex_hash, targ->cracked_hashes[j].hash)) {
                    pthread_mutex_lock(&targ->mutexes[j]);
                    if (targ->cracked_hashes[j].password == NULL ||
                        i < targ->cracked_hashes[j].candidate_index) {
                        if (targ->cracked_hashes[j].password != NULL)
                            free(targ->cracked_hashes[j].password);
                        targ->cracked_hashes[j].password = strdup(password);
                        targ->cracked_hashes[j].alg = algs[k];
                        targ->cracked_hashes[j].candidate_index = i;
                    }
                    pthread_mutex_unlock(&targ->mutexes[j]);
                }
            }
        }
    }
    return NULL;
}

void crack_hashed_passwords(char *password_list, char *hashed_list, char *output) {
    FILE *fp;
    char password[256];  // assume candidate passwords are at most 255 characters
    char hex_hash[2 * KEEP + 1];

  
    int n_hashed = 0;
    struct cracked_hash *cracked_hashes;
    fp = fopen(hashed_list, "r");
    assert(fp != NULL);
    while (fscanf(fp, "%s", hex_hash) == 1)
        n_hashed++;
    rewind(fp);
    cracked_hashes = malloc(n_hashed * sizeof(struct cracked_hash));
    assert(cracked_hashes != NULL);
    for (int i = 0; i < n_hashed; i++) {
        fscanf(fp, "%s", cracked_hashes[i].hash);
        cracked_hashes[i].password = NULL;
        cracked_hashes[i].alg = NULL;
        cracked_hashes[i].candidate_index = INT_MAX; // not yet cracked
    }
    fclose(fp);

  
    int n_candidates = 0;
    fp = fopen(password_list, "r");
    assert(fp != NULL);
    while (fscanf(fp, "%s", password) == 1)
        n_candidates++;
    rewind(fp);
    char **candidates = malloc(n_candidates * sizeof(char *));
    assert(candidates != NULL);
    int idx = 0;
    while (fscanf(fp, "%s", password) == 1) {
        candidates[idx++] = strdup(password);
    }
    fclose(fp);

  
    pthread_mutex_t *mutexes = malloc(n_hashed * sizeof(pthread_mutex_t));
    for (int i = 0; i < n_hashed; i++) {
        pthread_mutex_init(&mutexes[i], NULL);
    }

 
    int *next_candidate = malloc(sizeof(int));
    *next_candidate = 0;


    int n_threads = 6; // Adjust thread count as desired.
    pthread_t threads[n_threads];
    thread_arg targs[n_threads];
    for (int i = 0; i < n_threads; i++) {
        targs[i].n_candidates = n_candidates;
        targs[i].n_hashed = n_hashed;
        targs[i].candidates = candidates;
        targs[i].cracked_hashes = cracked_hashes;
        targs[i].mutexes = mutexes;
        targs[i].next_candidate = next_candidate;
        pthread_create(&threads[i], NULL, thread_crack, &targs[i]);
    }
    for (int i = 0; i < n_threads; i++) {
        pthread_join(threads[i], NULL);
    }


    fp = fopen(output, "w");
    assert(fp != NULL);
    for (int i = 0; i < n_hashed; i++) {
        if (cracked_hashes[i].password == NULL)
            fprintf(fp, "not found\n");
        else
            fprintf(fp, "%s:%s\n", cracked_hashes[i].password, cracked_hashes[i].alg);
    }
    fclose(fp);

    for (int i = 0; i < n_hashed; i++) {
        pthread_mutex_destroy(&mutexes[i]);
        free(cracked_hashes[i].password);
    }
    free(mutexes);
    free(cracked_hashes);
    for (int i = 0; i < n_candidates; i++) {
        free(candidates[i]);
    }
    free(candidates);
    free(next_candidate);
}
