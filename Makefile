.PHONY: all clean

all: main

main: main.c fuzzy_extractor.o monocypher/lib/libmonocypher.a
	gcc -ggdb3 main.c fuzzy_extractor.o ./monocypher/lib/libmonocypher.a -o main -lm

fuzzy_extractor.o: fuzzy_extractor.c
	gcc -c fuzzy_extractor.c -o fuzzy_extractor.o

monocypher/lib/libmonocypher.a:
	cd monocypher && $(MAKE)

clean:
	rm -f main fuzzy_extractor.o
	cd monocypher && $(MAKE) clean
