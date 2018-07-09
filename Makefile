all:
	gcc -L. -o rs.bin main.c loader.c -ldl
clean:
	rm -v main
