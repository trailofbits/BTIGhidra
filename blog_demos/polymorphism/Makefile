.PHONY: clean

polymorphism_example.so: polymorphism_example.c
	$(CC) --target=x86_64-pc-linux-gnu -fuse-ld=/usr/x86_64-linux-gnu/bin/ld -isystem/usr/x86_64-linux-gnu/include -shared polymorphism_example.c -o polymorphism_example.so

clean:
	rm polymorphism_example.so