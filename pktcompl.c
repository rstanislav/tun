#include <stdlib.h>
#include <sys/signalfd.h>
#include <aio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include "events.h"
#include "pktqueue.h"

static int pktcompl_event_handler(int fd, unsigned short flags, void *priv)
{
    int rc;
    struct signalfd_siginfo info;
    struct pkt *p;

    rc = read(fd, &info, sizeof (info));
    if (rc != sizeof (info)) {
        fprintf(stderr, "siginfo incomplete: %s\n", strerror(errno));
        return DISPATCH_ABORT;
    }

    p = (struct pkt *) info.ssi_ptr;


    if (p && p->compl_handler) {
        rc = aio_return(&p->aio);
        memset(&p->aio, 0, sizeof (p->aio));
        pkt_complete(p, rc);
        pkt_compl_clear(p);
    }

    return DISPATCH_CONTINUE;
}

struct event *pktcompl_event_create(struct dispatch *d)
{
    struct event *e;
    int fd;
    sigset_t sigmask;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGUSR1);
    sigprocmask(SIG_BLOCK, &sigmask, NULL);
    fd = signalfd(-1, &sigmask, 0);
    if (fd == -1) {
        fprintf(stderr, "signalfd() failed: %s\n", strerror(errno));
        return NULL;
    }

    e = event_create(d, fd, EVENT_READ, pktcompl_event_handler, NULL);
    if (!e) {
        close(fd);
        return NULL;
    }

    return e;
}

int pkt_async_read(int fd, struct pkt *p,
                   pktcompl_handler_t compl_handler, void *compl_priv)
{
    int rc;

    pkt_compl_set(p, compl_handler, compl_priv);

    p->aio.aio_fildes = fd;
    p->aio.aio_buf = p->buff;
    p->aio.aio_nbytes = p->buff_size;

    p->aio.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
    p->aio.aio_sigevent.sigev_signo = SIGUSR1;
    p->aio.aio_sigevent.sigev_value.sival_ptr = p;

    rc = aio_read(&p->aio);
    if (rc == -1) {
        fprintf(stderr, "aio_read() failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int pkt_async_write(int fd, struct pkt *p,
                    pktcompl_handler_t compl_handler, void *compl_priv)
{
    int rc;

    pkt_compl_set(p, compl_handler, compl_priv);

    p->aio.aio_fildes = fd;
    p->aio.aio_buf = p->buff;
    p->aio.aio_nbytes = p->pkt_size;

    p->aio.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
    p->aio.aio_sigevent.sigev_signo = SIGUSR1;
    p->aio.aio_sigevent.sigev_value.sival_ptr = p;

    rc = aio_write(&p->aio);
    if (rc == -1) {
        fprintf(stderr, "aio_write() failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

