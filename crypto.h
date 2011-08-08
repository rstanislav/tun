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

#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/blowfish.h>
#include <openssl/sha.h>

struct keyhdr
{
    unsigned short nlen;
    unsigned short elen;
    unsigned short dlen;
    unsigned short plen;
    unsigned short qlen;
    unsigned short dmp1len;
    unsigned short dmq1len;
    unsigned short iqmplen;
};

struct pubhdr
{
    unsigned short nlen;
    unsigned short elen;
};

size_t crypto_key_len(RSA *r);
int crypto_pack_key(RSA *r,
                    struct keyhdr *h,
                    unsigned char *data,
                    size_t len);
RSA *crypto_unpack_key(const struct keyhdr *h,
                       const unsigned char *data);
size_t crypto_pub_len(RSA *r);
int crypto_pack_pub(RSA *r,
                    struct pubhdr *h,
                    unsigned char *data,
                    size_t len);
RSA *crypto_unpack_pub(const struct pubhdr *h,
                       const unsigned char *data);
char *crypto_hash_str(const unsigned char *data,
                      unsigned long n);

#endif
