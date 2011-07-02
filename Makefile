
CC=gcc
CFLAGS=-W -Wall -g
LDFLAGS=

TARGET= tun
OBJS= iface.o events.o io.o tun.o

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

.PHONY = clean

clean:
	rm -f $(TARGET) $(OBJS)
    

