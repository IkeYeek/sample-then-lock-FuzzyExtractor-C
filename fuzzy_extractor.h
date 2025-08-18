#ifndef FUZZY_EXTRACTOR_H
#define FUZZY_EXTRACTOR_H

#include "monocypher/src/monocypher.h"

#include <stdbool.h>
#include <stdint.h>

#define TODO(msg)                                                              \
  printf("TODO: %s (file: %s, line: %d)\n", msg, __FILE__, __LINE__);          \
  exit(1);

/* Byte Arrays */
/**
 * A simple wrapper for a byte array allowing us to known its (supposed...)
 * length
 */
typedef struct byte_array_s {
  uint32_t len; // in bytes
  uint8_t *bytes;
} byte_array;

/**
 * Fills `holder` with random bytes
 */
void get_random_bytes(byte_array *holder);
/**
 * Returns a mask with exactly `n` uniformely chosen bits set to 1
 */
void get_random_sample_mask(byte_array *holder, uint32_t n);
/*
 * performs binary XOR `a` ^ `b`. `a` can be longer than `b`, in that case
 * exceeding bytes from `a` will stay the same (same as XORing with `b` padded
 * with 0s)
 */
void byte_array_padded_xor(byte_array *a, byte_array *b);
void byte_array_padded_and(byte_array *a, byte_array *b);
/*
 * ensures `bar` has at least `n` padding bytes (bytes set to 0)
 */
bool byte_array_has_n_padding_bytes(byte_array *bar, uint32_t n);
/**
 * copies `a->len` bytes from `b` to `a`
 */
bool byte_array_copy_bytes(byte_array *a, byte_array *b);

/* Digital Lockers */
/**
 * Generic holder for a single digital locker.
 * If locked, then consider "locked" member of union "locker", else consider
 * "unlocked".
 */
typedef struct digital_locker_s {
  bool locked;
  union {
    struct digital_locker_locked {
      byte_array *nonce;
      byte_array *cipher;
    } locked;
    byte_array *unlocked;
  } locker;
} digital_locker;

/**
 * Sets `locker` to `locked=true` and sets the pointers to its nonce and cipher
 * byte_arrays.
 * */
void dl_init_locked(digital_locker *locker, byte_array *nonce,
                    byte_array *cipher);
/**
 * Sets `locker` to `locked=false` and sets the pointer to its value byte_array
 */
void dl_init_unlocked(digital_locker *locker, byte_array *val);

/**
 * Locks the value `value` using `key` inside `locked`, using `security_param`
 * bytes of 0 padding
 */
void dl_lock(digital_locker *locked, byte_array *key, byte_array *value,
             uint32_t security_param);
/**
 * tries to unlock `locked` inside `unlocked` using `key`. `locked` is supposed
 * complete (has a valid nonce and cipher). Checks it has `security_param`
 * padding 0 bytes.
 */
bool dl_unlock(digital_locker *unlocked, byte_array *computed_cipher,
               digital_locker *locked, byte_array *key,
               uint32_t security_param);

/* Fuzzy Extractor */
typedef struct fuzzy_extractor_params_s {
  uint32_t security_param; // number of padding 0 bytes
  uint32_t r_bytes; // the size of the actual key output by the fuzzy extractor
  uint32_t l_nb;    // number of locks used
  uint32_t k_bytes; // number of bytes per sample
} fuzzy_extractor_params;

/**
 * used in place of digital_lockers structs when working with fuzzy extractor.
 * Struct of Arrays.
 */
typedef struct fuzzy_extractor_soa_s {
  byte_array *ciphers;
  byte_array *nonces;
  byte_array *helpers;
} fuzzy_extractor_soa;

typedef struct fuzzy_extractor_s {
  fuzzy_extractor_params params;
  fuzzy_extractor_soa soa;
} fuzzy_extractor;

void fuzzy_extractor_init(fuzzy_extractor *fe, fuzzy_extractor_params params,
                          byte_array *ciphers, byte_array *nonces,
                          byte_array *helpers);
void fuzzy_extractor_gen(fuzzy_extractor *fe, byte_array *r, byte_array *key,
                         byte_array *temp_key_holder);
bool fuzzy_extractor_rep(fuzzy_extractor *fe, byte_array *r_buff,
                         byte_array *key, byte_array *temp_key_holder,
                         byte_array *temp_cipher_holder);
#endif
