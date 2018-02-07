all:
	gcc -L. -o main main.c loader.c -ldl
clean:
	rm -v main
