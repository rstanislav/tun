#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "pktqueue.h"
#include "events.h"

static int setnonblock(int fd)
{
    long fl;

    fl = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

int io_dispatch(int tunfd, int sockfd)
{
    struct dispatch d;

    setnonblock(tunfd);
    setnonblock(sockfd);

    dispatch_init(&d);

    event_dispatch(&d);

    dispatch_cleanup(&d);

    return 0;
}

