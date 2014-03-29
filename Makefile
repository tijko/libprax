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

clean:
	rm *.o
