/*
 * Exam problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include "tools.c"

int main() {
	char buf[256];
	static const char secret[] = "I love UNIX programming!";
	unbuffered();
	printf("Show me the secret: ");
	if(read(0, buf, sizeof(buf)) > 0) {
		if(memcmp(secret, buf, sizeof(secret)) == 0) {
			showflag();
		} else {
			printf("No no no ...\n");
		}
	}
	return 0;
}
