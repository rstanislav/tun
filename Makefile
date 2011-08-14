CC=gcc
CFLAGS=-W -Wall -g

TUN=tun
TUN_OBJS=tun_crypto.o crypto.o handshake.o peer.o iface.o events.o io.o tun.o
TUN_CFLAGS=
TUN_LDFLAGS=-lcrypto

GENKEY=genkey
GENKEY_OBJS=crypto.o genkey.o
GENKEY_CFLAGS=
GENKEY_LDFLAGS=-lcrypto

all: $(GENKEY) $(TUN)

$(TUN): $(TUN_OBJS)
	@echo "  [LD] $@"
	@$(CC) $(TUN_LDFLAGS) -o $@ $^
$(TUN_OBJS): CFLAGS := $(CFLAGS) $(TUN_CFLAGS)

$(GENKEY): $(GENKEY_OBJS)
	@echo "  [LD] $@"
	@$(CC) $(GENKEY_LDFLAGS) -o $@ $^
$(GENKEY_OBJS): CFLAGS := $(CFLAGS) $(GENKEY_CFLAGS)

.PHONY = all clean distclean

.deps.mk:
	@echo "  [DEPS] $@"
	@$(CC) -MM -DGEN_DEPS $(TUN_CFLAGS) $(TUN_OBJS:.o=.c) > $@
	@$(CC) -MM -DGEN_DEPS $(GENKEY_CFLAGS) $(GENKEY_OBJS:.o=.c) >> $@

clean:
	rm -f $(TUN) $(TUN_OBJS)
	rm -f $(GENKEY) $(GENKEY_OBJS)

distclean:
	rm -f $(TUN) $(TUN_OBJS)
	rm -f $(GENKEY) $(GENKEY_OBJS)
	rm -f .deps.mk
    
%.o: %.c
	@echo "  [CC] $@"
	@$(CC) $(CFLAGS) -c $<

-include .deps.mk
