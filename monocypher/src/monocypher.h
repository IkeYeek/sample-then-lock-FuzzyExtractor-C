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
// Copyright (c) 2017-2019, Loup Vaillant
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
// Written in 2017-2019 by Loup Vaillant
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related neighboring rights to this software to the public domain
// worldwide.  This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along
// with this software.  If not, see
// <https://creativecommons.org/publicdomain/zero/1.0/>

#ifndef MONOCYPHER_H
#define MONOCYPHER_H

#include <stddef.h>
#include <stdint.h>

#ifdef MONOCYPHER_CPP_NAMESPACE
namespace MONOCYPHER_CPP_NAMESPACE {
#elif defined(__cplusplus)
extern "C" {
#endif

// Constant time comparisons
// -------------------------

// Return 0 if a and b are equal, -1 otherwise
int crypto_verify16(const uint8_t a[16], const uint8_t b[16]);
int crypto_verify32(const uint8_t a[32], const uint8_t b[32]);
int crypto_verify64(const uint8_t a[64], const uint8_t b[64]);

// Erase sensitive data
// --------------------
void crypto_wipe(void *secret, size_t size);

// Authenticated encryption
// ------------------------
void crypto_aead_lock(uint8_t *cipher_text, uint8_t mac[16],
                      const uint8_t key[32], const uint8_t nonce[24],
                      const uint8_t *ad, size_t ad_size,
                      const uint8_t *plain_text, size_t text_size);
int crypto_aead_unlock(uint8_t *plain_text, const uint8_t mac[16],
                       const uint8_t key[32], const uint8_t nonce[24],
                       const uint8_t *ad, size_t ad_size,
                       const uint8_t *cipher_text, size_t text_size);

// Authenticated stream
// --------------------
typedef struct {
  uint64_t counter;
  uint8_t key[32];
  uint8_t nonce[8];
} crypto_aead_ctx;

void crypto_aead_init_x(crypto_aead_ctx *ctx, const uint8_t key[32],
                        const uint8_t nonce[24]);
void crypto_aead_init_djb(crypto_aead_ctx *ctx, const uint8_t key[32],
                          const uint8_t nonce[8]);
void crypto_aead_init_ietf(crypto_aead_ctx *ctx, const uint8_t key[32],
                           const uint8_t nonce[12]);

void crypto_aead_write(crypto_aead_ctx *ctx, uint8_t *cipher_text,
                       uint8_t mac[16], const uint8_t *ad, size_t ad_size,
                       const uint8_t *plain_text, size_t text_size);
int crypto_aead_read(crypto_aead_ctx *ctx, uint8_t *plain_text,
                     const uint8_t mac[16], const uint8_t *ad, size_t ad_size,
                     const uint8_t *cipher_text, size_t text_size);

// General purpose hash (BLAKE2b)
// ------------------------------

// Direct interface
void crypto_blake2b(uint8_t *hash, size_t hash_size, const uint8_t *message,
                    size_t message_size);

void crypto_blake2b_keyed(uint8_t *hash, size_t hash_size, const uint8_t *key,
                          size_t key_size, const uint8_t *message,
                          size_t message_size);

// Incremental interface
typedef struct {
  // Do not rely on the size or contents of this type,
  // for they may change without notice.
  uint64_t hash[8];
  uint64_t input_offset[2];
  uint64_t input[16];
  size_t input_idx;
  size_t hash_size;
} crypto_blake2b_ctx;

void crypto_blake2b_init(crypto_blake2b_ctx *ctx, size_t hash_size);
void crypto_blake2b_keyed_init(crypto_blake2b_ctx *ctx, size_t hash_size,
                               const uint8_t *key, size_t key_size);
void crypto_blake2b_update(crypto_blake2b_ctx *ctx, const uint8_t *message,
                           size_t message_size);
void crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *hash);

#ifdef __cplusplus
}
#endif

#endif // MONOCYPHER_H
