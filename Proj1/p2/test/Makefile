C = gcc
CFLAGS = -g

test: test.o 
	$(CC) -o $@ $^ $(CFLAGS)

clean: 
	rm -f *.o test

.PHONY: clean
