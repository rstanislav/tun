
CC=gcc
CFLAGS=-W -Wall
LDFLAGS= -lrt

TARGET= tun
OBJS= pktcompl.o events.o io.o tun.o

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

.PHONY = clean

clean:
	rm -f $(TARGET) $(OBJS)
    

