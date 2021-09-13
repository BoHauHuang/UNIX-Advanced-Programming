/*
 * Exam problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include "tools.c"

#define	MAX_N	5
#define	NAMELEN	16

typedef struct user_s {
	int occupied;
	char *name;
}	user_t;

static user_t user[MAX_N];

int is_duplicated(char *buf) {
	int i;
	if(buf == NULL) return 0;
	for(i = 0; i < MAX_N; i++) {
		if(user[i].occupied == 0) continue; // ignore empty slots
		if(user[i].name == NULL)  continue; // ignore NULL
		if(buf == user[i].name)   continue; // don't check self
		if(strcmp(buf, user[i].name) == 0) return 1;
	}
	return 0;
}

void add_user() {
	int i, len;
	for(i = 0; i < MAX_N; i++) {
		if(user[i].occupied == 0) {
			if((user[i].name = malloc(NAMELEN)) == NULL) {
				printf("*** Memory allocation failed.\n");
				return;
			}
			printf("Enter username: ");
			if((len = read(0, user[i].name, NAMELEN-1)) > 0) {
				user[i].name[len-1] = '\0';
				if(is_duplicated(user[i].name)) {
					free(user[i].name);
					printf("*** Duplicated user registration is not allowed!\n");
				} else {
					user[i].occupied = 1;
					printf("*** User '%s' added.\n", user[i].name);
				}
				break;
			}
			printf("*** Bad input.\n");
			return;
		}
	}
	if(i == MAX_N) printf("*** No more user can be added.\n");
}

void delete_user() {
	int len, i = 0;
	char buf[16] = { 0 };
	printf("Which user do you want to delete (1-%d)? ", MAX_N);
	if((len = read(0, buf, sizeof(buf)-1)) > 0) i = strtol(buf, NULL, 0);
	if(i <= 0 || i > MAX_N) {
		printf("*** Bad index.\n");
		return;
	}
	free(user[i-1].name);
	user[i-1].occupied = 0;
	printf("*** User #%d deleted.\n", i);
}

void show_user() {
	int i, j, bad = 0;
	printf("*** List of users ***\n");
	for(i = 0; i < MAX_N; i++) {
		if(user[i].occupied) printf(" %d. %s\n", i+1, user[i].name);
	}
	// integrity check
	for(i = 0; i < MAX_N-1; i++) {
		if(user[i].occupied == 0) continue;
		if(user[i].name == NULL) continue;
		for(j = i+1; j < MAX_N; j++) {
			if(user[j].occupied == 0) continue;
			if(user[j].name == NULL) continue;
			if(strcmp(user[i].name, user[j].name) == 0) bad++;
		}
	}
	if(bad > 0) {
		printf("*** Oops, integrity check failed! Pleae report it to system administrator!\n");
		showflag();
	}
}

void menu() {
	printf("\n==== MENU ====\n"
		"a) add user\n"
		"d) delete user\n"
		"s) show users\n"
		"q) quit\n\n"
		"Enter your choice: ");
}

int main() {
	char buf[16];
	unbuffered();
	printf("*** Welcome to the AUP Online Registration System ***\n");
	do {
		menu();
		if(read(0, buf, sizeof(buf)) <= 0) break;
		if(buf[0] == 'a') add_user();
		if(buf[0] == 'd') delete_user();
		if(buf[0] == 's') show_user();
	} while(buf[0] != 'q');
	printf("\nThank you for using our system!\n");
	return 0;
}
