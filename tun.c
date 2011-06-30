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
    fprintf(stderr, "\t%s [-option] hostname port\n", progname);
    fprintf(stderr, "\t%s -l [-option] port\n", progname);
}

static int tun_alloc(char *ifname)
{
    struct ifreq ifr;
    int fd;
    int rc;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Failed to open /dev/net/tun: %s\n", strerror(errno));
        return fd;
    }

    memset(&ifr, 0, sizeof (ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, "tun%d", IFNAMSIZ);

    rc = ioctl(fd, TUNSETIFF, &ifr);
    if (rc) {
        fprintf(stderr, "Failed to create tunnel interface: %s\n", strerror(errno));
        return -1;
    }

    strcpy(ifname, ifr.ifr_name);

    return fd;
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

static int parse_opts(int argc, char **argv, struct sockaddr_in *addr, int *listen)
{
    int i;

    if (argc < 3) {
        fprintf(stderr, "%s needs at least 2 arguments\n", argv[0]);
        usage(argv[0]);
        return -1;
    }

    i = 1;
    while (i < argc) {
        if (!strcmp(argv[i], "-h")) {
            usage(argv[0]);
            exit(0);
        }

        if (!strcmp(argv[i], "-l")) {
            *listen = 1;
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
            } else if (!*listen && ((i + 2) == argc)) {
                if (!inet_aton(argv[i], &addr->sin_addr)) {
                    fprintf(stderr, "Bad IP address format: %s\n", argv[i]);
                    goto printusage;
                }
            } else {
                fprintf(stderr, "Unrecognized argument: %s\n", argv[i]);
                goto printusage;
            }
        }

        i++;
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

int init_queues(size_t buff_size, int max_buffs);
void cleanup_queues(void);
int work(int sockfd, int tunfd);

int main(int argc, char **argv)
{
    int tunfd, sockfd;
    char if_name[IFNAMSIZ];
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

    tunfd = tun_alloc(if_name);
    if (tunfd < 0)
        return -1;

    fprintf(stdout, "Created tunnel device %s\n", if_name);

    rc = init_queues(1500, 1024);
    if (rc) {
        fprintf(stdout, "Failed to create rx/tx queues.\n");
        return -1;
    }

    rc = work(sockfd, tunfd);

    cleanup_queues();

    close(tunfd);
    close(sockfd);

    return 0;
}

