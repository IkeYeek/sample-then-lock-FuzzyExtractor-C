#include "monocypher/src/monocypher.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#define TODO(msg)                                                              \
  printf("TODO: %s (file: %s, line: %d)\n", msg, __FILE__, __LINE__);          \
  exit(1);

char *to_hex(uint8_t *bytes, size_t len) {
  static char hex[] = "0123456789abcdef";
  size_t out_len = len * 2 + 1; // two hex chars per byte + NUL
  char *out = malloc(out_len);
  if (!out)
    return NULL;

  for (size_t i = 0; i < len; ++i) {
    uint8_t b = bytes[i];
    out[i * 2] = hex[b >> 4];
    out[i * 2 + 1] = hex[b & 0x0F];
  }
  out[out_len - 1] = '\0';
  return out;
}

typedef struct byte_array_s {
  uint32_t len; // in bytes
  uint8_t *bytes;
} byte_array;

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

void get_random_bytes(byte_array *holder);

/*
 * a can be longer than b, exceeding bytes will be ignored (which is equal to
 * them being equal to 0)
 */
void byte_array_padded_xor(byte_array *a, byte_array *b);
bool byte_array_has_n_padding_bytes(byte_array *bar, uint32_t n);
bool byte_array_copy_n_bytes(byte_array *a, byte_array *b);

void dl_init_locked(digital_locker *locker, byte_array *nonce,
                    byte_array *cipher);
void dl_init_unlocked(digital_locker *locker, byte_array *val);

void dl_lock(digital_locker *locked, byte_array *key, byte_array *value,
             uint32_t security_param);
bool dl_unlock(digital_locker *unlocked, byte_array *computed_cipher,
               digital_locker *locked, byte_array *key,
               uint32_t security_param);

void byte_array_padded_xor(byte_array *a, byte_array *b) {
  for (uint32_t i = 0; i < a->len; i++) {
    if (i < b->len) {
      a->bytes[i] = a->bytes[i] ^ b->bytes[i];
    }
  }
}

bool byte_array_has_n_padding_bytes(byte_array *bar, uint32_t n) {
  if (bar->len < n)
    return false;
  for (int i = bar->len - n; i < bar->len; i++) {
    if (bar->bytes[i] != 0)
      return false;
  }
  return true;
}
bool byte_array_copy_n_bytes(byte_array *a, byte_array *b) {
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
  // first we compute back PRF(key, nonce)
  crypto_blake2b_keyed(computed_cipher->bytes, computed_cipher->len,
                       locked->locker.locked.nonce->bytes,
                       locked->locker.locked.nonce->len, key->bytes, key->len);
  // then we xor it with our cipher
  byte_array_padded_xor(computed_cipher, locked->locker.locked.cipher);
  if (byte_array_has_n_padding_bytes(computed_cipher, security_param)) {
    // unlocking worked
    return byte_array_copy_n_bytes(unlocked->locker.unlocked, computed_cipher);
  }
  // it did not :'(
  return false;
}

typedef struct fuzzy_extractor_params_s {
  uint32_t security_param;
  uint32_t r_bytes; // the size of the actual key output by the fuzzy extractor
  uint32_t l_nb;    // number of locks used
  uint32_t k_bytes; // number of bytes per sample
} fuzzy_extractor_params;

void get_random_bytes(byte_array *holder) {
  ssize_t random_bytes = getrandom(holder->bytes, holder->len, 0);
  if (random_bytes != holder->len) {
    perror("couldn't generate enough bytes");
    exit(1);
  }
}

int main() {
  /* initialization */
  byte_array key = {
      .len = 1,
      .bytes = (uint8_t[]){0x33},
  };

  byte_array unlocked_bytes = {
      .len = 4,
      .bytes = (uint8_t[]){0xDE, 0xAD, 0xBE, 0xEF},
  };

  printf("original value: %s\n",
         to_hex(unlocked_bytes.bytes, unlocked_bytes.len));

  /* locking */
  uint8_t locked_nonce_bytes[16];
  byte_array locked_nonce = {
      .len = 16,
      .bytes = (uint8_t *)&locked_nonce_bytes,
  };
  uint8_t locked_cipher_bytes[5];
  byte_array locked_cipher = {
      .len = 5,
      .bytes = (uint8_t *)&locked_cipher_bytes,
  };
  digital_locker locked;
  dl_init_locked(&locked, &locked_nonce, &locked_cipher);

  dl_lock(&locked, &key, &unlocked_bytes, 1);
  printf("locked value: %s\nnonce: %s\n",
         to_hex(locked.locker.locked.cipher->bytes,
                locked.locker.locked.nonce->len),
         to_hex(locked.locker.locked.nonce->bytes,
                locked.locker.locked.nonce->len));

  byte_array maybe_unlocked_bytes = {
      .len = 4,
      .bytes = (uint8_t[4]){0, 0, 0, 0},
  };
  digital_locker maybe_unlocked;
  byte_array computed_cipher = {
      .len = 5,
      .bytes = (uint8_t[5]){},
  };
  dl_init_unlocked(&maybe_unlocked, &maybe_unlocked_bytes);
  dl_unlock(&maybe_unlocked, &computed_cipher, &locked, &key, 1);

  printf("unlocked value: %s\n", to_hex(maybe_unlocked.locker.unlocked->bytes,
                                        maybe_unlocked.locker.unlocked->len));
}
