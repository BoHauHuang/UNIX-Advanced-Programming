/*
 * Exam problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include "tools.c"

static jmp_buf jb;
static char buf[64];

int guess(int n) {
	volatile long long a, len;
       	a = n + rand() % 0xffff;
	setjmp(jb);
	printf("\nGuess the number: ");
	if((len = read(0, buf, sizeof(buf))) > 0) {
		buf[len] = '\0';
		if(a > n && strtoll(buf, NULL, 0) == a) {
			printf("\nBingo!\n");
			showflag();
			return 1;
		} else {
			printf("No no no ...\n");
		}
	}
	return 0;
}

void try_again(int n) {
	volatile long long v, len;
	printf("\nDo you want to try it again? ");
	if((len = read(0, buf, sizeof(buf))) > 0) {
		buf[len] = '\0';
		v = strtoll(buf, NULL, 0);
		if(buf[0] == 'Y' || buf[0] == 'y' || strcasecmp(buf, "yes") == 0 || v != 0)
			longjmp(jb, 1);
	}
	return;
}

int main(int argc, char *argv[]) {
	volatile int g;
	
	unbuffered();

	srand(time(0) ^ getpid());

	g = rand() & 0xffffff;

	if(guess(g) == 0) {
		try_again(g);
	}

	return 0;
}
