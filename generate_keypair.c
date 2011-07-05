#include <stdio.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/engine.h>

#include "crypto.h"

static void printbuff(const unsigned char *b, size_t l)
{
    size_t i;

    fprintf(stdout, "{ ");

    if (l) {
        for (i = 0; i < l - 1; i++) {
            fprintf(stdout, "0x%02x, ", b[i]);
        }
        fprintf(stdout, "0x%02x", b[l - 1]);
    }

    fprintf(stdout, "}");
}

int main(void)
{
    int rc;
    RSA *r;
    struct keypair kp;

    r = RSA_generate_key(2048, 17, NULL, NULL);
    if (!r) {
        fprintf(stderr, "Key generation failed\n");
        return 1;
    }

    rc = crypto_pack_key(r, &kp);
    RSA_free(r);
    if (!rc) {
        fprintf(stderr, "Failed to pack key\n");
        return 1;
    }

    fprintf(stdout, "const struct keypair KEYPAIR = {\n");
    fprintf(stdout, "    {\n      ");
    printbuff(kp.pub.n, sizeof (kp.pub.n)); fprintf(stdout, ",\n      ");
    printbuff(kp.pub.e, sizeof (kp.pub.e)); fprintf(stdout, "\n");
    fprintf(stdout, "    },\n    ");
    printbuff(kp.d, sizeof (kp.d)); fprintf(stdout, ",\n    ");
    printbuff(kp.p, sizeof (kp.p)); fprintf(stdout, ",\n    ");
    printbuff(kp.q, sizeof (kp.q)); fprintf(stdout, ",\n    ");
    printbuff(kp.dmp1, sizeof (kp.dmp1)); fprintf(stdout, ",\n    ");
    printbuff(kp.dmq1, sizeof (kp.dmq1)); fprintf(stdout, ",\n    ");
    printbuff(kp.iqmp, sizeof (kp.iqmp)); fprintf(stdout, "\n");
    fprintf(stdout, "};\n");

    memset(&kp, 0, sizeof (kp));
    return 0;
}

