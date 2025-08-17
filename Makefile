all: main.c monocypher
	gcc main.c -o main ./monocypher/lib/libmonocypher.a

monocypher:
	cd monocypher \
	make


