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

