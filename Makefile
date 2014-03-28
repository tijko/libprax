CC = gcc
CFLAGS = -c -g -fPIC -Wall
LDFLAGS = -shared

TARGET = shadow.so
SRCS = $(wildcard *.c) 
OBJS = shadow.o

$(TARGET): $(OBJS) 
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

$(OBJS): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS)

