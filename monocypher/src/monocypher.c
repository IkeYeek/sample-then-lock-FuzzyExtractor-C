// Monocypher version 4.0.2
//
// This file is dual-licensed.  Choose whichever licence you want from
// the two licences listed below.
//
// The first licence is a regular 2-clause BSD licence.  The second licence
// is the CC-0 from Creative Commons. It is intended to release Monocypher
// to the public domain.  The BSD licence serves as a fallback option.
//
// SPDX-License-Identifier: BSD-2-Clause OR CC0-1.0
//
// ------------------------------------------------------------------------
//
// Copyright (c) 2017-2020, Loup Vaillant
// All rights reserved.
//
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// ------------------------------------------------------------------------
//
// Written in 2017-2020 by Loup Vaillant
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related neighboring rights to this software to the public domain
// worldwide.  This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along
// with this software.  If not, see
// <https://creativecommons.org/publicdomain/zero/1.0/>

#include "monocypher.h"

#ifdef MONOCYPHER_CPP_NAMESPACE
namespace MONOCYPHER_CPP_NAMESPACE {
#endif

/////////////////
/// Utilities ///
/////////////////
#define FOR_T(type, i, start, end) for (type i = (start); i < (end); i++)
#define FOR(i, start, end) FOR_T(size_t, i, start, end)
#define COPY(dst, src, size) FOR(_i_, 0, size)(dst)[_i_] = (src)[_i_]
#define ZERO(buf, size) FOR(_i_, 0, size)(buf)[_i_] = 0
#define WIPE_CTX(ctx) crypto_wipe(ctx, sizeof(*(ctx)))
#define WIPE_BUFFER(buffer) crypto_wipe(buffer, sizeof(buffer))
#define MIN(a, b) ((a) <= (b) ? (a) : (b))
#define MAX(a, b) ((a) >= (b) ? (a) : (b))

typedef int8_t i8;
typedef uint8_t u8;
typedef int16_t i16;
typedef uint32_t u32;
typedef int32_t i32;
typedef int64_t i64;
typedef uint64_t u64;

static const u8 zero[128] = {0};

// returns the smallest positive integer y such that
// (x + y) % pow_2  == 0
// Basically, y is the "gap" missing to align x.
// Only works when pow_2 is a power of 2.
// Note: we use ~x+1 instead of -x to avoid compiler warnings
static size_t gap(size_t x, size_t pow_2) { return (~x + 1) & (pow_2 - 1); }

static u32 load24_le(const u8 s[3]) {
  return ((u32)s[0] << 0) | ((u32)s[1] << 8) | ((u32)s[2] << 16);
}

static u32 load32_le(const u8 s[4]) {
  return ((u32)s[0] << 0) | ((u32)s[1] << 8) | ((u32)s[2] << 16) |
         ((u32)s[3] << 24);
}

static u64 load64_le(const u8 s[8]) {
  return load32_le(s) | ((u64)load32_le(s + 4) << 32);
}

static void store32_le(u8 out[4], u32 in) {
  out[0] = in & 0xff;
  out[1] = (in >> 8) & 0xff;
  out[2] = (in >> 16) & 0xff;
  out[3] = (in >> 24) & 0xff;
}

static void store64_le(u8 out[8], u64 in) {
  store32_le(out, (u32)in);
  store32_le(out + 4, in >> 32);
}

static void load32_le_buf(u32 *dst, const u8 *src, size_t size) {
  FOR(i, 0, size) { dst[i] = load32_le(src + i * 4); }
}
static void load64_le_buf(u64 *dst, const u8 *src, size_t size) {
  FOR(i, 0, size) { dst[i] = load64_le(src + i * 8); }
}
static void store32_le_buf(u8 *dst, const u32 *src, size_t size) {
  FOR(i, 0, size) { store32_le(dst + i * 4, src[i]); }
}
static void store64_le_buf(u8 *dst, const u64 *src, size_t size) {
  FOR(i, 0, size) { store64_le(dst + i * 8, src[i]); }
}

static u64 rotr64(u64 x, u64 n) { return (x >> n) ^ (x << (64 - n)); }
static u32 rotl32(u32 x, u32 n) { return (x << n) ^ (x >> (32 - n)); }

static int neq0(u64 diff) {
  // constant time comparison to zero
  // return diff != 0 ? -1 : 0
  u64 half = (diff >> 32) | ((u32)diff);
  return (1 & ((half - 1) >> 32)) - 1;
}

static u64 x16(const u8 a[16], const u8 b[16]) {
  return (load64_le(a + 0) ^ load64_le(b + 0)) |
         (load64_le(a + 8) ^ load64_le(b + 8));
}
static u64 x32(const u8 a[32], const u8 b[32]) {
  return x16(a, b) | x16(a + 16, b + 16);
}
static u64 x64(const u8 a[64], const u8 b[64]) {
  return x32(a, b) | x32(a + 32, b + 32);
}
int crypto_verify16(const u8 a[16], const u8 b[16]) { return neq0(x16(a, b)); }
int crypto_verify32(const u8 a[32], const u8 b[32]) { return neq0(x32(a, b)); }
int crypto_verify64(const u8 a[64], const u8 b[64]) { return neq0(x64(a, b)); }

void crypto_wipe(void *secret, size_t size) {
  volatile u8 *v_secret = (u8 *)secret;
  ZERO(v_secret, size);
}

////////////////
/// BLAKE2 b ///
////////////////
static const u64 iv[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

static void blake2b_compress(crypto_blake2b_ctx *ctx, int is_last_block) {
  static const u8 sigma[12][16] = {
      {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
      {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
      {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
      {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
      {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
      {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
      {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
      {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
      {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
      {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
      {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
      {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
  };

  // increment input offset
  u64 *x = ctx->input_offset;
  size_t y = ctx->input_idx;
  x[0] += y;
  if (x[0] < y) {
    x[1]++;
  }

  // init work vector
  u64 v0 = ctx->hash[0];
  u64 v8 = iv[0];
  u64 v1 = ctx->hash[1];
  u64 v9 = iv[1];
  u64 v2 = ctx->hash[2];
  u64 v10 = iv[2];
  u64 v3 = ctx->hash[3];
  u64 v11 = iv[3];
  u64 v4 = ctx->hash[4];
  u64 v12 = iv[4] ^ ctx->input_offset[0];
  u64 v5 = ctx->hash[5];
  u64 v13 = iv[5] ^ ctx->input_offset[1];
  u64 v6 = ctx->hash[6];
  u64 v14 = iv[6] ^ (u64) ~(is_last_block - 1);
  u64 v7 = ctx->hash[7];
  u64 v15 = iv[7];

  // mangle work vector
  u64 *input = ctx->input;
#define BLAKE2_G(a, b, c, d, x, y)                                             \
  a += b + x;                                                                  \
  d = rotr64(d ^ a, 32);                                                       \
  c += d;                                                                      \
  b = rotr64(b ^ c, 24);                                                       \
  a += b + y;                                                                  \
  d = rotr64(d ^ a, 16);                                                       \
  c += d;                                                                      \
  b = rotr64(b ^ c, 63)
#define BLAKE2_ROUND(i)                                                        \
  BLAKE2_G(v0, v4, v8, v12, input[sigma[i][0]], input[sigma[i][1]]);           \
  BLAKE2_G(v1, v5, v9, v13, input[sigma[i][2]], input[sigma[i][3]]);           \
  BLAKE2_G(v2, v6, v10, v14, input[sigma[i][4]], input[sigma[i][5]]);          \
  BLAKE2_G(v3, v7, v11, v15, input[sigma[i][6]], input[sigma[i][7]]);          \
  BLAKE2_G(v0, v5, v10, v15, input[sigma[i][8]], input[sigma[i][9]]);          \
  BLAKE2_G(v1, v6, v11, v12, input[sigma[i][10]], input[sigma[i][11]]);        \
  BLAKE2_G(v2, v7, v8, v13, input[sigma[i][12]], input[sigma[i][13]]);         \
  BLAKE2_G(v3, v4, v9, v14, input[sigma[i][14]], input[sigma[i][15]])

#ifdef BLAKE2_NO_UNROLLING
  FOR(i, 0, 12) { BLAKE2_ROUND(i); }
#else
  BLAKE2_ROUND(0);
  BLAKE2_ROUND(1);
  BLAKE2_ROUND(2);
  BLAKE2_ROUND(3);
  BLAKE2_ROUND(4);
  BLAKE2_ROUND(5);
  BLAKE2_ROUND(6);
  BLAKE2_ROUND(7);
  BLAKE2_ROUND(8);
  BLAKE2_ROUND(9);
  BLAKE2_ROUND(10);
  BLAKE2_ROUND(11);
#endif

  // update hash
  ctx->hash[0] ^= v0 ^ v8;
  ctx->hash[1] ^= v1 ^ v9;
  ctx->hash[2] ^= v2 ^ v10;
  ctx->hash[3] ^= v3 ^ v11;
  ctx->hash[4] ^= v4 ^ v12;
  ctx->hash[5] ^= v5 ^ v13;
  ctx->hash[6] ^= v6 ^ v14;
  ctx->hash[7] ^= v7 ^ v15;
}

void crypto_blake2b_keyed_init(crypto_blake2b_ctx *ctx, size_t hash_size,
                               const u8 *key, size_t key_size) {
  // initial hash
  COPY(ctx->hash, iv, 8);
  ctx->hash[0] ^= 0x01010000 ^ (key_size << 8) ^ hash_size;

  ctx->input_offset[0] = 0; // beginning of the input, no offset
  ctx->input_offset[1] = 0; // beginning of the input, no offset
  ctx->hash_size = hash_size;
  ctx->input_idx = 0;
  ZERO(ctx->input, 16);

  // if there is a key, the first block is that key (padded with zeroes)
  if (key_size > 0) {
    u8 key_block[128] = {0};
    COPY(key_block, key, key_size);
    // same as calling crypto_blake2b_update(ctx, key_block , 128)
    load64_le_buf(ctx->input, key_block, 16);
    ctx->input_idx = 128;
  }
}

void crypto_blake2b_init(crypto_blake2b_ctx *ctx, size_t hash_size) {
  crypto_blake2b_keyed_init(ctx, hash_size, 0, 0);
}

void crypto_blake2b_update(crypto_blake2b_ctx *ctx, const u8 *message,
                           size_t message_size) {
  // Avoid undefined NULL pointer increments with empty messages
  if (message_size == 0) {
    return;
  }

  // Align with word boundaries
  if ((ctx->input_idx & 7) != 0) {
    size_t nb_bytes = MIN(gap(ctx->input_idx, 8), message_size);
    size_t word = ctx->input_idx >> 3;
    size_t byte = ctx->input_idx & 7;
    FOR(i, 0, nb_bytes) {
      ctx->input[word] |= (u64)message[i] << ((byte + i) << 3);
    }
    ctx->input_idx += nb_bytes;
    message += nb_bytes;
    message_size -= nb_bytes;
  }

  // Align with block boundaries (faster than byte by byte)
  if ((ctx->input_idx & 127) != 0) {
    size_t nb_words = MIN(gap(ctx->input_idx, 128), message_size) >> 3;
    load64_le_buf(ctx->input + (ctx->input_idx >> 3), message, nb_words);
    ctx->input_idx += nb_words << 3;
    message += nb_words << 3;
    message_size -= nb_words << 3;
  }

  // Process block by block
  size_t nb_blocks = message_size >> 7;
  FOR(i, 0, nb_blocks) {
    if (ctx->input_idx == 128) {
      blake2b_compress(ctx, 0);
    }
    load64_le_buf(ctx->input, message, 16);
    message += 128;
    ctx->input_idx = 128;
  }
  message_size &= 127;

  if (message_size != 0) {
    // Compress block & flush input buffer as needed
    if (ctx->input_idx == 128) {
      blake2b_compress(ctx, 0);
      ctx->input_idx = 0;
    }
    if (ctx->input_idx == 0) {
      ZERO(ctx->input, 16);
    }
    // Fill remaining words (faster than byte by byte)
    size_t nb_words = message_size >> 3;
    load64_le_buf(ctx->input, message, nb_words);
    ctx->input_idx += nb_words << 3;
    message += nb_words << 3;
    message_size -= nb_words << 3;

    // Fill remaining bytes
    FOR(i, 0, message_size) {
      size_t word = ctx->input_idx >> 3;
      size_t byte = ctx->input_idx & 7;
      ctx->input[word] |= (u64)message[i] << (byte << 3);
      ctx->input_idx++;
    }
  }
}

void crypto_blake2b_final(crypto_blake2b_ctx *ctx, u8 *hash) {
  blake2b_compress(ctx, 1); // compress the last block
  size_t hash_size = MIN(ctx->hash_size, 64);
  size_t nb_words = hash_size >> 3;
  store64_le_buf(hash, ctx->hash, nb_words);
  FOR(i, nb_words << 3, hash_size) {
    hash[i] = (ctx->hash[i >> 3] >> (8 * (i & 7))) & 0xff;
  }
  WIPE_CTX(ctx);
}

void crypto_blake2b_keyed(u8 *hash, size_t hash_size, const u8 *key,
                          size_t key_size, const u8 *message,
                          size_t message_size) {
  crypto_blake2b_ctx ctx;
  crypto_blake2b_keyed_init(&ctx, hash_size, key, key_size);
  crypto_blake2b_update(&ctx, message, message_size);
  crypto_blake2b_final(&ctx, hash);
}

void crypto_blake2b(u8 *hash, size_t hash_size, const u8 *msg,
                    size_t msg_size) {
  crypto_blake2b_keyed(hash, hash_size, 0, 0, msg, msg_size);
}

#ifdef MONOCYPHER_CPP_NAMESPACE
}
#endif
