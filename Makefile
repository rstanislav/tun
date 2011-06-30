
CC=gcc
CFLAGS=-W -Wall
LDFLAGS=

TARGET= tun
OBJS= events.o io.o tun.o

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

.PHONY = clean

clean:
	rm -f $(TARGET) $(OBJS)
    

