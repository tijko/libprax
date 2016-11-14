CC = gcc
CFLAGS = -c -g -fPIC -Wall
LDFLAGS = -shared
HEADER = prax.h

.PHONY:
	install uninstall clean

%.o: %.c
	$(CC) $^ $(CFLAGS)

libprax.so: *.o
	$(CC) $^ -o libprax.so $(LDFLAGS)

install:
	cp $(HEADER) /usr/include/     
	mv libprax.so /usr/lib/
	chmod 0755 /usr/lib/libprax.so
	ldconfig -n /usr/lib/libprax.so

uninstall:
	rm /usr/lib/libprax.so
	rm /usr/include/$(HEADER)
	ldconfig

clean:
	rm *.o
