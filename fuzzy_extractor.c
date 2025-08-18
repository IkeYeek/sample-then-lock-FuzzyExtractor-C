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

void get_random_bytes(byte_array *holder) {
  ssize_t random_bytes = getrandom(holder->bytes, holder->len, 0);
  if (random_bytes != holder->len) {
    FAIL("couldn't generate enough bytes");
  }
}

static uint32_t random_u32(void) {
  uint8_t buf[4];
  byte_array rnd = {4, buf};
  get_random_bytes(&rnd);
  return (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) |
         ((uint32_t)buf[3] << 24);
}

void get_random_sample_mask(byte_array *holder, uint32_t n) {
  if (!holder || holder->len == 0)
    return;

  uint32_t total = holder->len * 8u;

  if (n == 0) {
    memset(holder->bytes, 0, holder->len);
    return;
  }
  if (n >= total) {
    memset(holder->bytes, 0xFF, holder->len);
    return;
  }

  memset(holder->bytes, 0, holder->len);

  uint32_t remaining = total;
  uint32_t to_pick = n;
  for (uint32_t idx = 0; idx < total && to_pick > 0; ++idx) {
    uint32_t r;
    uint32_t limit = UINT32_MAX - (UINT32_MAX % remaining);
    do {
      r = random_u32();
    } while (r >= limit);
    r %= remaining;

    if (r < to_pick) {
      holder->bytes[idx >> 3] |= (uint8_t)(1u << (idx & 7));
      --to_pick;
    }

    --remaining;
  }
}

void byte_array_padded_xor(byte_array *a, byte_array *b) {
  for (uint32_t i = 0; i < a->len && i < b->len; i++) {
    a->bytes[i] = a->bytes[i] ^ b->bytes[i];
  }
}

void byte_array_padded_and(byte_array *a, byte_array *b) {
  for (uint32_t i = 0; i < a->len && i < b->len; i++) {
    a->bytes[i] = a->bytes[i] & b->bytes[i];
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

void fuzzy_extractor_init(fuzzy_extractor *fe, fuzzy_extractor_params params,
                          byte_array *ciphers, byte_array *nonces,
                          byte_array *helpers) {
  fe->params = params;
  fe->soa.ciphers = ciphers;
  fe->soa.nonces = nonces;
  fe->soa.helpers = helpers;
}

void fuzzy_extractor_gen(fuzzy_extractor *fe, byte_array *r, byte_array *key,
                         byte_array *temp_key_holder) {
  if (r->len != fe->params.r_bytes) {
    FAIL("wrong r buffer len");
  }
  if (key->len != temp_key_holder->len) {
    FAIL("wrong temp_key_holder len");
  }
  // first we choose a random r
  get_random_bytes(r);
  // then for every l
  for (uint32_t l_idx = 0; l_idx < fe->params.l_nb; l_idx++) {
    // we get a random sample mask of size k
    get_random_sample_mask(&fe->soa.helpers[l_idx], fe->params.k_bytes * 8);
    // then we make a mask of our key
    byte_array_copy_bytes(temp_key_holder, key);
    byte_array_padded_and(temp_key_holder, &fe->soa.helpers[l_idx]);
    digital_locker curr_lock;
    dl_init_locked(&curr_lock, &fe->soa.nonces[l_idx], &fe->soa.ciphers[l_idx]);
    dl_lock(&curr_lock, temp_key_holder, r, fe->params.security_param);
  }
}

bool fuzzy_extractor_rep(fuzzy_extractor *fe, byte_array *r_buff,
                         byte_array *key, byte_array *temp_key_holder,
                         byte_array *temp_cipher_holder) {
  if (r_buff->len != fe->params.r_bytes) {
    FAIL("wrong r buffer len");
  }
  if (key->len != temp_key_holder->len) {
    FAIL("wrong temp_key_holder len");
  }
  for (uint32_t l_idx = 0; l_idx < fe->params.l_nb; l_idx++) {
    // we load the right parameters from our soa
    byte_array cipher = fe->soa.ciphers[l_idx];
    byte_array nonce = fe->soa.nonces[l_idx];
    byte_array helper = fe->soa.helpers[l_idx];
    digital_locker curr_locked;
    // initialize the current lock
    dl_init_locked(&curr_locked, &nonce, &cipher);
    byte_array_copy_bytes(temp_key_holder, key);
    byte_array_padded_and(temp_key_holder, &helper);
    digital_locker unlocked;
    // and the unlocked one
    dl_init_unlocked(&unlocked, r_buff);
    // then try to unlock the locked into the unlocked one and return true if it
    // works
    if (dl_unlock(&unlocked, temp_cipher_holder, &curr_locked, temp_key_holder,
                  fe->params.security_param)) {
      return true;
    }
  }
  return false;
}
