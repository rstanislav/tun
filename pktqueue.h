#include <sys/queue.h>
#include <stdlib.h>
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

struct pkt;
typedef void (*pktcompl_handler_t)(struct pkt *, void *, size_t count);

struct pkt
{
    SIMPLEQ_ENTRY(pkt) link;

    size_t buff_size;
    size_t pkt_size;
    char *buff;

    pktcompl_handler_t compl_handler;
    void *compl_priv;
    struct aiocb aio;
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

    return p;
}

static inline void pkt_free(struct pkt *p)
{
    free(p->buff);
    free(p);
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

static inline void pkt_compl_set(struct pkt *p, pktcompl_handler_t h,
                                 void *priv)
{
    p->compl_handler = h;
    p->compl_priv = priv;
}

static inline void pkt_compl_clear(struct pkt *p)
{
    p->compl_handler = NULL;
    p->compl_priv = NULL;
}

static inline void pkt_complete(struct pkt *p, size_t count)
{
    p->compl_handler(p, p->compl_priv, count);
}

