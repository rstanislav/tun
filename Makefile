CC=gcc
CFLAGS=-W -Wall -g

TUN_LDFLAGS=
TUN_CFLAGS=
TUN=tun
TUN_OBJS= handshake.o peer.o iface.o events.o io.o tun.o

all: .deps.mk $(TUN)

$(TUN): $(TUN_OBJS)
	@echo -e "  [LD] $@"
	@$(CC) $(TUN_LDFLAGS) -o $@ $^
$(TUN_OBJS): CFLAGS := $(CFLAGS) $(TUN_CFLAGS)

.PHONY = deps clean distclean

-include .deps.mk

.deps.mk deps:
	@echo -e "  [DEPS] .deps.mk"
	@$(CC) -MM $(TUN_CFLAGS) $(TUN_OBJS:.o=.c) > .deps.mk

clean:
	rm -f $(TUN) $(TUN_OBJS)

distclean:
	rm -f $(TUN) $(TUN_OBJS)
	rm -f .deps.mk
    
%.o: %.c
	@echo -e "  [CC] $@"
	@$(CC) $(CFLAGS) -c $<

