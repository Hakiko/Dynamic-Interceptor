CC=gcc
CXX_FLAGS=-O2 -Wall -Wextra

all: libinterceptor.so

libinterceptor.so: interceptor.c interceptor.h
	$(CC) $(CXX_FLAGS) interceptor.c -o libinterceptor.so -fPIC -shared -ldl

clean:
	rm -f libinterceptor.so
