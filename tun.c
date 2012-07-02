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
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

static void usage(char *progname)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s [OPTION] hostname port\n", progname);
    fprintf(stderr, "    %s -l [OPTION] port\n", progname);
    fprintf(stderr, "Options:\n");
#if 0 /* FIXME */
    fprintf(stderr, "    -k <filename>          Path to the file containing the private RSA key to use\n"
                    "                           for securing communication with peer. If none is given,\n"
                    "                           communication will be sent in plain text.\n");
    fprintf(stderr, "    -a <digest list>       Comma separated list of SHA-1 public key digests that %s\n"
                    "                           will automatically accept when establishing a secure\n"
                    "                           channel with the remote host. If the remote host's public\n"
                    "                           key digest is not listed, the user will be prompted to\n"
                    "                           accept the remote host RSA key on the standard output.\n",
                    progname);
#endif
}

static int sock_alloc(int listen, struct sockaddr_in *addr)
{
    int fd;
    int rc;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    addr->sin_family = AF_INET;

    if (fd < 0) {
        fprintf(stderr, "Failed to open socket: %s\n", strerror(errno));
        return fd;
    }

    if (listen) {
        addr->sin_addr.s_addr = INADDR_ANY;
        rc = bind(fd, (struct sockaddr *) addr, sizeof (*addr));
        if (rc) {
            fprintf(stderr, "Failed to bind: %s\n", strerror(errno));
            return -1;
        }
    } else {
        rc = connect(fd, (struct sockaddr *) addr, sizeof (*addr));
        if (rc) {
            fprintf(stderr, "Failed to connect: %s\n", strerror(errno));
            return -1;
        }
    }

    return fd;
}

/*
 * My little poney ugly function.
 */
static int parse_opts(int argc, char **argv, struct sockaddr_in *addr, int *listen)
{
    int i;
    int a = 0, p = 0;

    i = 1;
    while (i < argc) {
        if (!strcmp(argv[i], "-h")) {
            usage(argv[0]);
            exit(0);
        }

        if (!strcmp(argv[i], "-l")) {
            *listen = 1;
#if 0 /* FIXME */
        } else if (!strcmp(argv[i], "-k")) {
            i++;
            if (crypto_load_key(argv[i])) {
                fprintf(stderr, "Failed to load key file %s: %s\n", argv[i],
                        strerror(errno));
                goto printusage;
            }
        } else if (!strcmp(argv[i], "-a")) {
            i++;
            if (crypto_accept_list(argv[i])) {
                fprintf(stderr, "Syntax error in accept list: %s\n", argv[i]);
                goto printusage;
            }
#endif
        } else {
            if (argv[i][0] == '-') {
                fprintf(stderr, "Unrecognized option: %s\n", argv[i]);
                goto printusage;
            }

            if ((i + 1) == argc) {
                short n;

                if (1 != sscanf(argv[i], "%hi", &n)) {
                    fprintf(stderr, "Bad port number: %s\n", argv[i]);
                    goto printusage;
                }
                addr->sin_port = htons(n);
                p = 1;
            } else if (!*listen && ((i + 2) == argc)) {
                if (!inet_aton(argv[i], &addr->sin_addr)) {
                    fprintf(stderr, "Bad IP address format: %s\n", argv[i]);
                    goto printusage;
                }
                a = 1;
            } else {
                fprintf(stderr, "Unrecognized argument: %s\n", argv[i]);
                goto printusage;
            }
        }

        i++;
    }

    if (!p || (!*listen && !a)) {
        fprintf(stderr, "Missing parameters\n");
        usage(argv[0]);
        return -1;
    }

    if (*listen && addr->sin_addr.s_addr) {
        fprintf(stderr, "Both listen switch and remote IP address provided\n");
        goto printusage;
    }

    if (!*listen && (addr->sin_addr.s_addr == 0)) {
        fprintf(stderr, "No remote IP address provided\n");
        goto printusage;
    }

    return 0;
printusage:
    usage(argv[0]);
    return -1;
}

int io_dispatch(int sockfd, struct sockaddr_in *remote);

int main(int argc, char **argv)
{
    int sockfd;
    int listen = 0;
    struct sockaddr_in addr;
    int rc = 0;

    memset(&addr, 0, sizeof (addr));
    rc = parse_opts(argc, argv, &addr, &listen);
    if (rc) {
        return rc;
    }

    sockfd = sock_alloc(listen, &addr);
    if (sockfd < 0)
        return -1;

    rc = io_dispatch(sockfd, listen ? NULL : &addr);

    close(sockfd);

    return 0;
}

