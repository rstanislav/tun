#ifndef EVENTS_H_
#define EVENTS_H_

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

#ifndef LIST_FOREACH_SAFE
# define LIST_FOREACH_SAFE(var, head, field, tvar)                   \
    for ((var) = LIST_FIRST((head));                                 \
         (var) && ((tvar) = LIST_NEXT((var), field), 1);             \
         (var) = (tvar))
#endif

enum event_control
{
    EVCTL_READ_STALL = 0,
    EVCTL_READ_RESTART,
    EVCTL_WRITE_STALL,
    EVCTL_WRITE_RESTART
};

struct event *event_create(struct dispatch *d, int fd, unsigned short flags,
                           event_handler_t handler, void *priv);
int event_control(struct dispatch *d, struct event *e, int ctl);
void event_delete(struct dispatch *d, struct event *e);
int dispatch_init(struct dispatch *d);
void dispatch_cleanup(struct dispatch *d);
int event_dispatch(struct dispatch *d);

#endif /* EVENTS_H_ */
