all: main

main: main.c fuzzy_extractor.o monocypher/lib/libmonocypher.a
	gcc main.c fuzzy_extractor.o ./monocypher/lib/libmonocypher.a -o main

fuzzy_extractor.o: fuzzy_extractor.c
	gcc -c fuzzy_extractor.c -o fuzzy_extractor.o

monocypher/lib/libmonocypher.a:
	cd monocypher && make

clean:
	rm main fuzzy_extractor.o
