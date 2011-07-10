#include <strings.h>
#include <linux/if_tun.h>
#include <stdio.h>

#include "peer.h"
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
    hdr->proto = htons(HANDSHAKE_PROTO_ID);
    pkt->pkt_size = sizeof (struct tun_pi) + sizeof (struct pubhdr);
    pkt->pkt_size += crypto_pack_pub(privkey, pubhdr,
                                     (void *)(pubhdr + 1),
                                     pkt->buff_size - pkt->pkt_size);
    pkt_set_compl(pkt, handshake_pkt_complete, NULL);

    peer_send(p, pkt);
}

static int handshake_gen_key(struct peer *p, unsigned char *buf, int len)
{
    int rc;

    rc = RAND_bytes(buf, len);
    if (rc != 1)
        return -1;
    BF_set_key(&p->key, len, buf);

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
    hdr->proto = htons(HANDSHAKE_PROTO_ID);

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
    handshake_send_pub(p);
}

void handshake_reset(struct peer *p)
{
    if (p->pubkey)
        RSA_free(p->pubkey);
}

int handshake_accept(struct peer *p, struct pkt *pkt)
{
    struct tun_pi *hdr = (struct tun_pi *)pkt->buff;

    if (!p->pubkey) {
        struct pubhdr *phdr = (struct pubhdr *)(hdr + 1);
        unsigned char *data = (void *)(phdr + 1);
        char *hash;

        if (pkt->pkt_size < (sizeof (hdr) + sizeof (phdr)))
            return -1;
        if (pkt->pkt_size < (sizeof (hdr) + sizeof (phdr) +
                             phdr->nlen + phdr->elen))
            return -1;

        p->pubkey = crypto_unpack_pub(phdr, data);

        hash = crypto_hash_str(data, phdr->nlen + phdr->elen);
        PEER_LOG(p, "Public key digest: %s", hash);
        free(hash);

        handshake_send_key(p);

        return 1;
    }

    return -1;
}

int handshake_request(struct peer *p, struct pkt *pkt)
{
    struct tun_pi *hdr = (struct tun_pi *)pkt->buff;

    if (!p->pubkey) {
        struct pubhdr *phdr = (struct pubhdr *)(hdr + 1);
        unsigned char *data = (void *)(phdr + 1);
        char *hash;
        unsigned char *key;
        unsigned char keysha1[SHA_DIGEST_LENGTH];
        int len;

        if (pkt->pkt_size < (sizeof (hdr) + sizeof (phdr)))
            return -1;
        if (pkt->pkt_size < (sizeof (hdr) + sizeof (phdr) +
                             phdr->nlen + phdr->elen))
            return -1;

        p->pubkey = crypto_unpack_pub(phdr, data);

        if (pkt->pkt_size < (sizeof (hdr) + sizeof (phdr) +
                             phdr->nlen + phdr->elen +
                             RSA_size(privkey)))
            return -1;

        hash = crypto_hash_str(data, phdr->nlen + phdr->elen);
        PEER_LOG(p, "Public key digest: %s", hash);
        free(hash);

        key = malloc(RSA_size(privkey));
        if (!key)
            return -1;

        data += crypto_pub_len(p->pubkey);
        len = (pkt->buff + pkt->pkt_size) - (char *)data;
        RSA_private_decrypt(len, data, key, privkey,
                            RSA_PKCS1_OAEP_PADDING);
        SHA1(key, 16, keysha1);
        if (memcmp(key + 16, keysha1, SHA_DIGEST_LENGTH)) {
            fprintf(stdout, "Invalid Key checksum\n");
            free(key);
            return -1;
        }
        BF_set_key(&p->key, 16, key);
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

