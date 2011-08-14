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

#include <unistd.h>
#include <linux/if_tun.h>

#include "crypto.h"
#include "peer.h"
#include "iface.h"

RSA *privkey = NULL;

void crypto_init(void)
{
    int fd;
    int rc;
    unsigned char r[16];

    RAND_seed(r, 16);
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return;
    do {
        rc = read(fd, r, 16);
        if (rc != 16)
            return;
        RAND_seed(r, 16);

        rc = RAND_bytes(r, 16);
    } while (!rc);
    close (fd);
}

int crypto_load_key(const char *filename)
{
    int fd;
    struct keyhdr hdr;
    int rc;
    int len;
    unsigned char *data = NULL;
    int i;
    char *hash;

    fd = open(filename, O_RDONLY);
    if (fd == -1)
        return -1;

    rc = read(fd, &hdr, sizeof (hdr));
    if (rc != sizeof (hdr)) {
        close(fd);
        return -1;
    }

    len = hdr.nlen + hdr.elen + hdr.dlen + hdr.plen + hdr.qlen +
          hdr.dmp1len + hdr.dmq1len + hdr.iqmplen;
    data = malloc(len);
    if (!data) {
        close(fd);
        return -1;
    }

    i = 0;
    do {
        rc = read(fd, data + i, len - i);
        if (rc == -1) {
            free(data);
            close(fd);
            return -1;
        }
        i += rc;
    } while (i < len);

    hash = crypto_hash_str(data, hdr.nlen + hdr.elen);
    if (hash) {
        fprintf(stdout, "Loaded RSA key pair. Public key SHA digest: %s\n",
                hash);
        free(hash);
    }

    privkey = crypto_unpack_key(&hdr, data);

    free(data);
    close(fd);
    return !privkey;
}

int crypto_accept_key(const unsigned char *data, unsigned long len)
{
    char c;
    int rc;
    unsigned char digest[SHA_DIGEST_LENGTH];
    int i;

    SHA1(data, len, digest);

    fprintf(stdout, "Remote host public key digest: ");
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        fprintf(stdout, "%02x", digest[i]);
    }
    fprintf(stdout, "\n");

    {
        char *line = NULL;
        size_t n = 0;

        do {
            fprintf(stdout, "Do you want to accept public key ? (y/n):");
            rc = getline(&line, &n, stdin);
            if (rc <= 0)
                return 0;

            rc = sscanf(line, "%c\n", &c);
            if (rc != 1)
                return 0;
        } while (c != 'y' && c != 'n');

        if (line)
            free(line);
    }

    if (c == 'n')
        return 0;

    return 1;
}

