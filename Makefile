CC=gcc
CFLAGS=-W -Wall -g -O2

TUN=tun
TUN_OBJS=peer.o iface.o events.o io.o tun.o
TUN_CFLAGS=
TUN_LDFLAGS=

all: $(TUN)

$(TUN): $(TUN_OBJS)
	@echo "  [LD] $@"
	@$(CC) $(TUN_LDFLAGS) -o $@ $^
$(TUN_OBJS): CFLAGS := $(CFLAGS) $(TUN_CFLAGS)

.PHONY = all clean distclean

.deps.mk:
	@echo "  [DEPS] $@"
	@$(CC) -MM -DGEN_DEPS $(TUN_CFLAGS) $(TUN_OBJS:.o=.c) > $@

clean:
	rm -f $(TUN) $(TUN_OBJS)

distclean:
	rm -f $(TUN) $(TUN_OBJS)
	rm -f .deps.mk
    
%.o: %.c
	@echo "  [CC] $@"
	@$(CC) $(CFLAGS) -c $<

-include .deps.mk
