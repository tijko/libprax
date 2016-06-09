CC = gcc
CFLAGS = -c -g -fPIC -Wall
LDFLAGS = -shared

HEADER = prax.h
TARGET = libprax.so
SRCS = $(wildcard *.c) 
OBJS = $(patsubst %.c, %.o, $(SRCS))

.PHONY:
	install uninstall clean

$(TARGET): $(OBJS) 
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

$(OBJS): $(SRCS)
	$(CC) $(SRCS) $(CFLAGS)

install:
	cp $(HEADER) /usr/include/     
	mv $(TARGET) /usr/lib/
	chmod 0755 /usr/lib/$(TARGET)
	ldconfig -n /usr/lib/$(TARGET)

uninstall:
	rm /usr/lib/$(TARGET)
	rm /usr/include/$(HEADER)
	ldconfig

clean:
	rm *.o
