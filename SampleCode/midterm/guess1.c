/*
 * Exam problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include "tools.c"

static char buf[64];
static int g;

int main() {
	unbuffered();
	srand(time(0) ^ getpid());
	g = rand() & 0xffffff;
	printf("\nGuess the number: ");
	gets(buf);
	if(strtol(buf, NULL, 0) == g) {
		printf("\nBingo!\n");
		showflag();
	}
	_exit(0);
	return 0;
}
