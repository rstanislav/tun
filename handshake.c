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

#include <strings.h>
#include <linux/if_tun.h>
#include <stdio.h>

#include "peer.h"
#include "tun_crypto.h"
#include "crypto.h"

extern RSA *privkey;

static void handshake_pkt_complete(struct pkt *pkt, void *priv)
{
    (void)priv;

    pkt_free(pkt);
}

static void handshake_send_pub(struct peer *p)
{
    struct pkt *pkt;
    struct tun_pi *hdr;
    struct pubhdr *pubhdr;

    pkt = pkt_alloc(sizeof (struct tun_pi) +
                    sizeof (struct pubhdr) +
                    crypto_pub_len(privkey));
    if (!pkt)
        return;
    hdr = (struct tun_pi *)pkt->buff;
    pubhdr = (struct pubhdr *)(hdr + 1);
    hdr->flags = 0;
    hdr->proto = htons(RSA_HANDSHAKE_PROTO);
    pkt->pkt_size = sizeof (struct tun_pi) + sizeof (struct pubhdr);
    pkt->pkt_size += crypto_pack_pub(privkey, pubhdr,
                                     (void *)(pubhdr + 1),
                                     pkt->buff_size - pkt->pkt_size);
    pkt_set_compl(pkt, handshake_pkt_complete, NULL);

    peer_send(p, pkt);
}

static void handshake_send_hello(struct peer *p)
{
    struct pkt *pkt;
    struct tun_pi *hdr;
    char message[5] = "HELLO";

    pkt = pkt_alloc(sizeof (struct tun_pi) + sizeof (message));
    if (!pkt)
        return;
    hdr = (struct tun_pi *)pkt->buff;
    hdr->flags = 0;
    hdr->proto = htons(PLAINTEXT_HANDSHAKE_PROTO);
    pkt->pkt_size = sizeof (struct tun_pi) + sizeof (message);
    strncpy((void *)(hdr + 1), message, sizeof (message));
    pkt_set_compl(pkt, handshake_pkt_complete, NULL);

    peer_send(p, pkt);
}

static int handshake_gen_key(struct peer *p, unsigned char *buf, int len)
{
    int rc;

    rc = RAND_bytes(buf, len);
    if (rc != 1)
        return -1;
    p->key = malloc(sizeof (BF_KEY));
    if (!p->key)
        return -1;
    BF_set_key(p->key, len, buf);

    return 0;
}

static void handshake_send_key(struct peer *p)
{
    struct pkt *pkt;
    struct tun_pi *hdr;
    struct pubhdr *pubhdr;
    unsigned char key[16 + SHA_DIGEST_LENGTH];
    int rc;

    pkt = pkt_alloc(sizeof (struct tun_pi) +
                    sizeof (struct pubhdr) +
                    crypto_pub_len(privkey) +
                    RSA_size(p->pubkey));
    if (!pkt)
        return;

    hdr = (struct tun_pi *)pkt->buff;
    pubhdr = (struct pubhdr *)(hdr + 1);
    hdr->proto = htons(RSA_HANDSHAKE_PROTO);
    hdr->flags = 0;

    pkt->pkt_size = sizeof (struct tun_pi) +
                    sizeof (struct pubhdr);
    pkt->pkt_size += crypto_pack_pub(privkey, pubhdr,
                                     (void *)(pubhdr + 1),
                                     pkt->buff_size - pkt->pkt_size);

    rc = handshake_gen_key(p, key, 16);
    if (rc) {
        pkt_free(pkt);
        return;
    }
    SHA1(key, 16, key + 16);
    rc = RSA_public_encrypt(sizeof (key), key,
                            (unsigned char *)pkt->buff + pkt->pkt_size,
                            p->pubkey, RSA_PKCS1_OAEP_PADDING);
    if (rc == -1) {
        pkt_free(pkt);
        return;
    }
    pkt->pkt_size += rc;

    pkt_set_compl(pkt, handshake_pkt_complete, NULL);

    peer_send(p, pkt);
}

void handshake_init(struct peer *p)
{
    if (privkey)
        handshake_send_pub(p);
    else
        handshake_send_hello(p);
}

void handshake_reset(struct peer *p)
{
    if (p->pubkey)
        RSA_free(p->pubkey);
}

int handshake_accept(struct peer *p, struct pkt *pkt)
{
    struct tun_pi *hdr = (struct tun_pi *)pkt->buff;

    if (privkey && ntohs(hdr->proto) == PLAINTEXT_HANDSHAKE_PROTO) {
        PEER_LOG(p, "Peer is attempting to establish connection in plain text");
        return -1;
    }

    if (!privkey && ntohs(hdr->proto) == RSA_HANDSHAKE_PROTO) {
        PEER_LOG(p, "Peer is attempting to perform RSA key exchange");
        return -1;
    }

    if (!privkey) {
        /* Plaintext */
        unsigned char *data = (void *)(hdr + 1);
        int msglen = pkt->pkt_size - sizeof (hdr);

        if (!strncmp((char *)data, "HELLO", msglen)) {
            handshake_send_hello(p);
            return 1;
        }
    } else if (!p->pubkey) {
        /* RSA */
        struct pubhdr *phdr = (struct pubhdr *)(hdr + 1);
        unsigned char *data = (void *)(phdr + 1);

        if (pkt->pkt_size < (sizeof (hdr) + sizeof (phdr)))
            return -1;
        if (pkt->pkt_size < (sizeof (hdr) + sizeof (phdr) +
                             phdr->nlen + phdr->elen))
            return -1;

        p->pubkey = crypto_unpack_pub(phdr, data);

        if (!crypto_accept_key(data, phdr->nlen + phdr->elen))
            return -1;

        handshake_send_key(p);

        return 1;
    }

    return -1;
}

int handshake_request(struct peer *p, struct pkt *pkt)
{
    struct tun_pi *hdr = (struct tun_pi *)pkt->buff;

    if (privkey && ntohs(hdr->proto) == PLAINTEXT_HANDSHAKE_PROTO) {
        PEER_LOG(p, "Peer is attempting to establish connection in plain text");
        return -1;
    }

    if (!privkey && ntohs(hdr->proto) == RSA_HANDSHAKE_PROTO) {
        PEER_LOG(p, "Peer is attempting to perform RSA key exchange");
        return -1;
    }

    if (!privkey) {
        /* Plaintext */
        unsigned char *data = (void *)(hdr + 1);
        int msglen = pkt->pkt_size - sizeof (hdr);

        if (!strncmp((char *)data, "HELLO", msglen)) {
            return 1;
        }
    } else if (!p->pubkey) {
        /* RSA */
        struct pubhdr *phdr = (struct pubhdr *)(hdr + 1);
        unsigned char *data = (void *)(phdr + 1);
        unsigned char *key;
        unsigned char keysha1[SHA_DIGEST_LENGTH];
        int len;

        if (pkt->pkt_size < (sizeof (hdr) + sizeof (phdr)))
            return -1;
        if (pkt->pkt_size < (sizeof (hdr) + sizeof (phdr) +
                             phdr->nlen + phdr->elen))
            return -1;

        p->pubkey = crypto_unpack_pub(phdr, data);

        if (pkt->pkt_size < (sizeof (*hdr) + sizeof (*phdr) +
                             crypto_pub_len(p->pubkey) +
                             RSA_size(privkey)))
            return -1;

        if (!crypto_accept_key(data, phdr->nlen + phdr->elen))
            return -1;

        key = malloc(RSA_size(privkey));
        if (!key)
            return -1;

        data += crypto_pub_len(p->pubkey);
        len = (pkt->buff + pkt->pkt_size) - (char *)data;
        RSA_private_decrypt(len, data, key, privkey,
                            RSA_PKCS1_OAEP_PADDING);
        SHA1(key, 16, keysha1);
        if (memcmp(key + 16, keysha1, SHA_DIGEST_LENGTH)) {
            PEER_LOG(p, "Invalid Key checksum");
            free(key);
            return -1;
        }

        p->key = malloc(sizeof (BF_KEY));
        if (!p->key) {
            free(key);
            return -1;
        }
        BF_set_key(p->key, 16, key);
        free(key);

        return 1;
    }

    return -1;
}

int handshake_connected(struct peer *p, struct pkt *pkt)
{
    struct tun_pi *hdr = (struct tun_pi *)pkt->buff;

    (void)p;
    (void)hdr;

    return -1;
}

