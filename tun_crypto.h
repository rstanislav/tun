/*
 *  Copyright (c) 2011, Julian Pidancet <julian.pidancet@gmail.com>
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *  3. Neither the name of Julian Pidancet nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *  COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 *  AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 *  OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE.
 */

#ifndef TUN_CRYPTO_H_
#define TUN_CRYPTO_H_

#include <openssl/blowfish.h>

#define MAGIC_IVEC {0, 1, 3, 3, 7, 0, 0, 255}

void crypto_init(void);
int crypto_load_key(const char *filename);
int crypto_accept_list(const char *list);
int crypto_accept_key(const unsigned char *data, unsigned long len);

static inline void encrypt_data(unsigned char *data,
                                int len,
                                void *key)
{
    unsigned char ivec[8] = MAGIC_IVEC;
    int num = 0;

    BF_cfb64_encrypt(data, data, len, key, ivec, &num, BF_ENCRYPT);
}

static inline void decrypt_data(unsigned char *data,
                                int len,
                                void *key)
{
    unsigned char ivec[8] = MAGIC_IVEC;
    int num = 0;

    BF_cfb64_encrypt(data, data, len, key, ivec, &num, BF_DECRYPT);
}

#endif /* TUN_CRYPTO_H_ */

