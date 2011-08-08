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

#ifndef GEN_DEPS
static const struct
{
    struct keyhdr hdr;
    unsigned char data[];
} binkey = {
#include "priv.key"
};
#endif

RSA *privkey = NULL;

#define MAGIC_IVEC {0, 1, 3, 3, 7, 0, 0, 255}

void crypto_init(void)
{
    int fd;
    int rc;
    unsigned char r[16];

    privkey = crypto_unpack_key(&binkey.hdr, binkey.data);

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

void peer_encrypt(struct pkt *pkt, void *priv)
{
    struct peer *p = priv;
    unsigned char ivec[8] = MAGIC_IVEC;
    int num = 0;
    struct tun_pi *hdr = (void *)pkt->buff;
    unsigned char *data = (void *)(hdr + 1);
    int len = pkt->pkt_size - sizeof (*hdr);

    BF_cfb64_encrypt(data, data, len, &p->key, ivec, &num, BF_ENCRYPT);

    p->tx_count++;
    p->tx(pkt, &p->addr);
}

void peer_decrypt(struct peer *p, struct pkt *pkt)
{
    unsigned char ivec[8] = MAGIC_IVEC;
    int num = 0;
    struct tun_pi *hdr = (void *)pkt->buff;
    unsigned char *data = (void *)(hdr + 1);
    int len = pkt->pkt_size - sizeof (*hdr);

    BF_cfb64_encrypt(data, data, len, &p->key, ivec, &num, BF_DECRYPT);

    iface_rx_schedule(p->iface, pkt);
}

