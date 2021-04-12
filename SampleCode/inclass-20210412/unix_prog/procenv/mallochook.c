#include <malloc.h>
#include <stdio.h>

void my_init() {
	printf("done.\n");
}

void (*__malloc_initialize_hook)(void) = my_init;

int main() {
	printf("hello\n");
	return 0;
}

