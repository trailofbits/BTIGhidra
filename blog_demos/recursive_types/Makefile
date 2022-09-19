.PHONY: all clean

all: list_test.so list_test-x86_64.so

list_test.so: 
	$(CC) list_test.c -shared --target=i686-linux-gnu -fuse-ld=/usr/i686-linux-gnu/bin/ld -isystem/usr/i686-linux-gnu/include -o list_test.so

list_test-x86_64.so: 
	$(CC) list_test.c -shared --target=x86_64-linux-gnu -fuse-ld=/usr/x86_64-linux-gnu/bin/ld -isystem/usr/x86_64-linux-gnu/include -o list_test-x86_64.so


clean:
	rm list_test list_test-x86_64