#include "fuzzy_extractor.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#define FAIL(msg)                                                              \
  fprintf(stderr, "%s (file: %s, line: %d)\n", msg, __FILE__, __LINE__);       \
  exit(1);

void byte_array_padded_xor(byte_array *a, byte_array *b) {
  for (uint32_t i = 0; i < a->len && i < b->len; i++) {
    a->bytes[i] = a->bytes[i] ^ b->bytes[i];
  }
}

bool byte_array_has_n_padding_bytes(byte_array *bar, uint32_t n) {
  if (bar->len < n)
    return false;
  for (uint32_t i = bar->len - n; i < bar->len; i++) {
    if (bar->bytes[i] != 0)
      return false;
  }
  return true;
}
bool byte_array_copy_bytes(byte_array *a, byte_array *b) {
  if (b->len < a->len)
    return false;
  memcpy(a->bytes, b->bytes, a->len);
  return true;
}

void dl_init_locked(digital_locker *locker, byte_array *nonce,
                    byte_array *cipher) {
  locker->locked = true;
  locker->locker.locked.cipher = cipher;
  locker->locker.locked.nonce = nonce;
}

void dl_init_unlocked(digital_locker *locker, byte_array *val) {
  locker->locked = false;
  locker->locker.unlocked = val;
}

void dl_lock(digital_locker *locked, byte_array *key, byte_array *value,
             uint32_t security_param) {
  if (locked->locker.locked.cipher->len != value->len + security_param) {
    FAIL("|cipher| must equal |value| + security_param")
  }
  // we get a random nonce
  get_random_bytes(locked->locker.locked.nonce);
  // then we compute PRF(key, nonce)
  crypto_blake2b_keyed(locked->locker.locked.cipher->bytes,
                       locked->locker.locked.cipher->len,
                       locked->locker.locked.nonce->bytes,
                       locked->locker.locked.nonce->len, key->bytes, key->len);
  // we pad the value with `security_param` zeros to be able to tell with a
  // probability of $1-2^{-security_param}$ that the locker has been
  // unlocked or not. a `security_param = 1` (1 byte / 8 bits) value makes you
  // sure to be able to tell if unlocked failed with a probability of ~0.996
  // which seems ok to me, and xor it with the cipher (all in place)
  byte_array_padded_xor(locked->locker.locked.cipher, value);
}

bool dl_unlock(digital_locker *unlocked, byte_array *computed_cipher,
               digital_locker *locked, byte_array *key,
               uint32_t security_param) {
  if (unlocked->locker.unlocked->len !=
      locked->locker.locked.cipher->len - security_param) {
    FAIL("|unlocked| must equal |cipher| - security_param");
  }
  if (computed_cipher->len != locked->locker.locked.cipher->len) {
    FAIL("|computed_cipher| must equal |cipher|");
  }
  // first we compute back PRF(key, nonce)
  crypto_blake2b_keyed(computed_cipher->bytes, computed_cipher->len,
                       locked->locker.locked.nonce->bytes,
                       locked->locker.locked.nonce->len, key->bytes, key->len);
  // then we xor it with our cipher
  byte_array_padded_xor(computed_cipher, locked->locker.locked.cipher);
  if (byte_array_has_n_padding_bytes(computed_cipher, security_param)) {
    // unlocking worked
    return byte_array_copy_bytes(unlocked->locker.unlocked, computed_cipher);
  }
  // it did not :'(
  return false;
}

void get_random_bytes(byte_array *holder) {
  ssize_t random_bytes = getrandom(holder->bytes, holder->len, 0);
  if (random_bytes != holder->len) {
    FAIL("couldn't generate enough bytes");
  }
}
