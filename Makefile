CC = gcc
CFLAGS = -c -g -fPIC -Wall
LDFLAGS = -shared

TARGET = libshadow.so
SRCS = $(wildcard *.c) 
OBJS = $(patsubst %.c, %.o, $(SRCS))

$(TARGET): $(OBJS) 
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

$(OBJS): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS)

install:
	mv $(TARGET) /usr/lib/
	ldconfig -n /usr/lib/$(TARGET)

uninstall:
	rm /usr/lib/$(TARGET)

clean:
	rm *.o
