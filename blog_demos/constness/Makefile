.PHONY: clean

const_pointer.so: const_pointers.c
	$(CC) --target=x86_64-pc-linux-gnu -fuse-ld=/usr/x86_64-linux-gnu/bin/ld -isystem/usr/x86_64-linux-gnu/include -shared const_pointers.c -o const_pointer.so

clean:
	rm const_pointer.so