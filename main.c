#include "fuzzy_extractor.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

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

/* Allocate a copy; returns NULL on OOM */
static byte_array *byte_array_copy(const byte_array *in) {
  if (!in)
    return NULL;
  byte_array *out = malloc(sizeof(*out));
  if (!out)
    return NULL;
  out->len = in->len;
  if (in->len == 0) {
    out->bytes = NULL;
    return out;
  }
  out->bytes = malloc(in->len);
  if (!out->bytes) {
    free(out);
    return NULL;
  }
  memcpy(out->bytes, in->bytes, in->len);
  return out;
}

static void byte_array_free(byte_array *b) {
  if (!b)
    return;
  free(b->bytes);
  free(b);
}

/* Flip n distinct random bits in a copy; returns allocated byte_array* or NULL
 */
byte_array *noise_simple(const byte_array *in, uint32_t n) {
  if (!in)
    return NULL;
  uint64_t total_bits = (uint64_t)in->len * 8ULL;
  if (n > total_bits)
    return NULL;

  byte_array *out = byte_array_copy(in);
  if (!out)
    return NULL;

  if (n == 0 || total_bits == 0)
    return out;

  /* lazy seed */
  static int seeded = 0;
  if (!seeded) {
    srand((unsigned)time(NULL));
    seeded = 1;
  }

  size_t bitmap_bytes = (size_t)((total_bits + 7) / 8);
  uint8_t *chosen = calloc(bitmap_bytes, 1);
  if (!chosen) {
    byte_array_free(out);
    return NULL;
  }

  uint32_t flipped = 0;
  while (flipped < n) {
    uint64_t idx = (uint64_t)rand() % total_bits;
    size_t b = (size_t)(idx >> 3);          /* byte index in bitmap */
    uint8_t m = (uint8_t)(1u << (idx & 7)); /* bit mask in bitmap */
    if (chosen[b] & m)
      continue; /* already chosen */
    chosen[b] |= m;

    uint32_t byte_index = (uint32_t)(idx / 8);
    uint8_t bit_in_byte = (uint8_t)(idx % 8);
    out->bytes[byte_index] ^= (uint8_t)(1u << bit_in_byte);
    flipped++;
  }

  free(chosen);
  return out;
}

/* Hamming distance (bit-wise). Returns UINT32_MAX on error. */
uint32_t hamming_simple(const byte_array *a, const byte_array *b) {
  if (!a || !b)
    return UINT32_MAX;
  if (a->len != b->len)
    return UINT32_MAX;
  uint32_t dist = 0;
  for (uint32_t i = 0; i < a->len; ++i) {
    uint8_t x = a->bytes[i] ^ b->bytes[i];
    dist += (uint32_t)__builtin_popcount((unsigned)x);
  }
  return dist;
}

void test_dl() {
  /* initialization */
  byte_array key = {
      .len = 1,
      .bytes = (uint8_t[]){0x33, 0x45},
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
  byte_array key2 = {
      .len = 1,
      .bytes = (uint8_t[]){0x33, 0x45},
  };
  if (dl_unlock(&maybe_unlocked, &computed_cipher, &locked, &key2, 1)) {
    printf("unlocked value: %s\n", to_hex(maybe_unlocked.locker.unlocked->bytes,
                                          maybe_unlocked.locker.unlocked->len));
  } else {
    printf("unlocking failed!\n");
  }
}

int main() {
  uint32_t l_val = 16;
  uint32_t ciphers_len = 17;
  uint32_t nonces_len = 16;
  uint32_t key_len = 16;
  uint32_t helpers_len = 17;

  fuzzy_extractor_params params = {
      .l_nb = l_val,
      .k_bytes = 12,
      .r_bytes = 16,
      .security_param = 1,
  };

  uint8_t ciphers_raw[l_val][ciphers_len];
  uint8_t nonces_raw[l_val][nonces_len];
  uint8_t helpers_raw[l_val][helpers_len];

  byte_array ciphers[l_val];
  byte_array nonces[l_val];
  byte_array helpers[l_val];

  for (uint32_t i = 0; i < params.l_nb; i++) {
    ciphers[i].len = ciphers_len;
    ciphers[i].bytes = ciphers_raw[i];
    nonces[i].len = nonces_len;
    nonces[i].bytes = nonces_raw[i];
    helpers[i].len = helpers_len;
    helpers[i].bytes = helpers_raw[i];
  }

  fuzzy_extractor fe;
  fuzzy_extractor_init(&fe, params, ciphers, nonces, helpers);

  uint8_t r_buff[params.r_bytes];
  uint8_t key_buff[key_len];
  uint8_t temp_key_buff[key_len];
  uint8_t temp_cipher_buff[ciphers_len];
  byte_array r = {
      .len = params.r_bytes,
      .bytes = r_buff,
  };
  byte_array key = {
      .len = 16,
      .bytes = key_buff,
  };
  byte_array temp_key = {
      .len = 16,
      .bytes = temp_key_buff,
  };
  get_random_bytes(&key);
  byte_array temp_cipher = {
      .len = ciphers_len,
      .bytes = temp_cipher_buff,
  };
  byte_array *key_p = noise_simple(&key, 4);
  fuzzy_extractor_gen(&fe, &r, &key, &temp_key);

  // for (uint32_t l_idx = 0; l_idx < params.l_nb; l_idx++) {
  //   printf("Lock N° %d/%d\n", l_idx + 1, params.l_nb);
  //   printf("\tNonce: %s\n",
  //          to_hex(fe.soa.nonces[l_idx].bytes, fe.soa.nonces[l_idx].len));
  //   printf("\tCipher: %s\n",
  //          to_hex(fe.soa.ciphers[l_idx].bytes, fe.soa.ciphers[l_idx].len));
  //   printf("\tHelper: %s\n",
  //          to_hex(fe.soa.helpers[l_idx].bytes, fe.soa.helpers[l_idx].len));
  // }

  printf("Key a: %s\nKey b: %s\nr=%s\n", to_hex(key.bytes, key.len),
         to_hex(key_p->bytes, key_p->len), to_hex(r.bytes, r.len));
  if (fuzzy_extractor_rep(&fe, &r, key_p, &temp_key, &temp_cipher)) {
    printf("unlocked!\nr=%s\n", to_hex(r.bytes, r.len));
  } else {
    printf("unlocking failed!\n");
  }

  return 0;
}
