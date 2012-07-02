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

#ifndef PKTQUEUE_H_
#define PKTQUEUE_H_

#include <sys/queue.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <aio.h>

#ifdef USE_LOCKS
# include <pthread.h>
typedef pthread_spinlock_t lock_t;
# define lock_init(x) pthread_spin_init(x)
# define lock(x) pthread_spin_lock(x)
# define unlock(x) pthread_spin_unlock(x)
#else
typedef char lock_t[0];
#define lock_init(x)
#define lock(x)
#define unlock(x)
#endif

#define PKT_INFO_SZ 40

struct pkt;
typedef void (*compl_handler_t)(struct pkt *, void *);

struct pkt
{
    SIMPLEQ_ENTRY(pkt) link;

    size_t buff_size;
    size_t pkt_size;
    char *buff;

    struct {
        compl_handler_t handler;
        void *priv;
    } compl;

    void *dest;
};

struct pktqueue
{
    SIMPLEQ_HEAD(,pkt) h;
    lock_t l;
    size_t pkt_count;
    size_t total_mem;
    size_t pkt_mem;
};

static inline void pktqueue_init(struct pktqueue *pq)
{
    SIMPLEQ_INIT(&pq->h);
    lock_init(&pq->l);
    pq->pkt_count = 0;
    pq->total_mem = 0;
    pq->pkt_mem = 0;
}

static inline void pkt_free(struct pkt *p)
{
    free(p->buff);
    free(p);
}

static inline void pkt_complete_default(struct pkt *pkt, void *priv)
{
    (void)priv;
    pkt_free(pkt);
}

static inline void pkt_set_compl(struct pkt *p, compl_handler_t h,
                                 void *priv)
{
    p->compl.handler = h;
    p->compl.priv = priv;
}

static inline struct pkt *pkt_alloc(size_t size)
{
    struct pkt *p;

    p = calloc(1, sizeof (*p));
    if (!p)
        return NULL;
    p->buff = calloc(1, size);
    if (!p->buff)
        return NULL;
    p->buff_size = size;
    pkt_set_compl(p, pkt_complete_default, NULL);

    return p;
}

static inline void pkt_complete(struct pkt *p)
{
    compl_handler_t h = p->compl.handler;
    void *priv = p->compl.priv;

    p->compl.handler = NULL;
    p->compl.priv = NULL;

    if (h)
        h(p, priv);
}

static inline int pktqueue_enqueue(struct pktqueue *pq, struct pkt *p)
{
    lock(&pq->l);
    SIMPLEQ_INSERT_TAIL(&pq->h, p, link);
    unlock(&pq->l);
    ++pq->pkt_count;
    pq->total_mem += p->buff_size;
    pq->pkt_mem += p->pkt_size;
    return 0;
}

static inline struct pkt *pktqueue_dequeue(struct pktqueue *pq)
{
    struct pkt *p;

    lock(&pq->l);
    p = SIMPLEQ_FIRST (&pq->h);
    if (!p)
        goto unlock;
    SIMPLEQ_REMOVE_HEAD(&pq->h, link);
    --pq->pkt_count;
    pq->total_mem -= p->buff_size;
    pq->pkt_mem -= p->pkt_size;

unlock:
    unlock(&pq->l);
    return p;
}

static inline void pkt_set_dest(struct pkt *p, void *dest)
{
    p->dest = dest;
}

static inline void *pkt_get_dest(struct pkt *p)
{
    return p->dest;
}

#endif /* PKTQUEUE_H_ */
