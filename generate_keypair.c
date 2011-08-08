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

#include <stdio.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/engine.h>

#include "crypto.h"

int main(void)
{
    int rc;
    RSA *r;
    struct keyhdr h;
    unsigned char buff[2048];
    int i = 0;
    char *hash;

    r = RSA_generate_key(2048, 65537, NULL, NULL);
    if (!r) {
        fprintf(stderr, "Key generation failed\n");
        return 1;
    }

    rc = crypto_pack_key(r, &h, buff, 2048);
    RSA_free(r);
    if (rc == -1) {
        fprintf(stderr, "Failed to pack key\n");
        return 1;
    }

    hash = crypto_hash_str(buff, h.nlen + h.elen);
    fprintf(stderr, "Public key SHA digest: %s\n", hash);
    free(hash);

    fprintf(stdout, "{\n");
    fprintf(stdout, "  .nlen = %d,\n", h.nlen);
    fprintf(stdout, "  .elen = %d,\n", h.elen);
    fprintf(stdout, "  .dlen = %d,\n", h.dlen);
    fprintf(stdout, "  .plen = %d,\n", h.plen);
    fprintf(stdout, "  .qlen = %d,\n", h.qlen);
    fprintf(stdout, "  .dmp1len = %d,\n", h.dmp1len);
    fprintf(stdout, "  .dmq1len = %d,\n", h.dmq1len);
    fprintf(stdout, "  .iqmplen = %d\n", h.iqmplen);
    fprintf(stdout, "},\n");

    fprintf(stdout, "{\n");
    if (rc)
        fprintf(stdout, "  0x%02x", buff[i++]);
    while (i < rc) {
        if (i % 16)
            fprintf(stdout, ", 0x%02x", buff[i++]);
        else
            fprintf(stdout, ",\n  0x%02x", buff[i++]);
    }
    fprintf(stdout, "\n}\n");

    memset(buff, 0, sizeof (buff));
    return 0;
}

