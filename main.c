#include "fuzzy_extractor.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

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

int main() {
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
