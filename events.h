#include <sys/queue.h>

#define EVENT_READ 0x1
#define EVENT_WRITE 0x2
#define EVENT_EDGE_TRIGGERED 0x80

#define DISPATCH_CONTINUE 0
#define DISPATCH_ABORT -1
typedef int (*event_handler_t)(int, unsigned short, void *);

struct event
{
    event_handler_t handler;
    int fd;
    void *priv;
    int flags;
    LIST_ENTRY(event) link;
};

struct dispatch
{
    int epfd;

    LIST_HEAD(,event) handlers;
};

#define	LIST_FOREACH_SAFE(var, tmp, head, field)                        \
        for ((var) = ((head)->lh_first),                                \
                (tmp) = (var) ? (var)->field.le_next : NULL;            \
             (var);                                                     \
	     (var) = (tmp),                                             \
                (tmp) = (var) ? (var)->field.le_next : NULL)            \

struct event *event_create(struct dispatch *d, int fd, unsigned short flags,
                           event_handler_t handler, void *priv);
void event_delete(struct dispatch *d, struct event *e);
int dispatch_init(struct dispatch *d);
void dispatch_cleanup(struct dispatch *d);
int event_dispatch(struct dispatch *d);
