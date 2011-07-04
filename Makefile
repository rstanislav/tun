CC=gcc
CFLAGS=-W -Wall -g
LDFLAGS=

TARGET= tun
OBJS= handshake.o peer.o iface.o events.o io.o tun.o

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

.PHONY = deps clean distclean

-include .deps.mk

deps:
	$(CC) -MM $(CFLAGS) $(OBJS:.o=.c) > .deps.mk

clean:
	rm -f $(TARGET) $(OBJS)

distclean:
	rm -f .deps.mk
    
