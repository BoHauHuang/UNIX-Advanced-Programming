/*
 * Exam problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <seccomp.h>
#include <sys/types.h>
#include <sys/wait.h>

extern void envvar(int);

char buf[8192];
static pid_t child = 0;

#define CHECKENV	"checkenv"
#define	xerror(x)	{ perror(x); exit(-1); }

static void
setup_filter() {
	scmp_filter_ctx ctx;
	/* only the following syscalls are allowed */
	if((ctx = seccomp_init(SCMP_ACT_KILL)) == NULL) xerror("seccomp_init");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0) < 0)		xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_load(ctx) < 0) xerror("seccomp_load");
}

void sigchld(int s) {
	if(child > 0 && waitpid(child, &s, 0) > 0) {
		if(WIFSIGNALED(s)) { printf("child terminated with signal = %d.\n", WTERMSIG(s)); exit(-1); }
		child = 0;
	}
}
void killchild()	{ if(child > 0) kill(child, SIGKILL); }
void sigterm(int s)	{ killchild(); exit(-1); }

int check_envvar(char *secret) {
	int s, len = 0, ret = -1;

	snprintf(buf, sizeof(buf), "/proc/%d/environ", child);
	if((s = open(buf, O_RDONLY)) < 0) return -1;
	if((len = read(s, buf, sizeof(buf))) <= 0) perror("read");
	close(s);
	if(len <= 0) return -1;

	for(s = 0; s < len; s = s + strlen(&buf[s]) + 1) {
		if(strncmp(&buf[s], "SECRET=", 7) == 0) {
			if(strcmp(secret, &buf[s+7]) == 0) return 0;
			break;
		}
	}

	return -1;
}

int main() {
	int fdin[2], fdout[2];

	if(getenv("SHORTCUT") != NULL) {
		envvar(1);
		exit(0);
	}

	atexit(killchild);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	signal(SIGCHLD, sigchld);
	signal(SIGTERM, sigterm);
	signal(SIGINT, sigterm);

	do { // create a random secret
		unsigned long long i, x = 0ULL;
		srand(time(0) ^ getpid());
		for(i = 0; i < 4; i++) { x <<= 16; x |= rand() ^ 0xffff; }
		snprintf(buf, sizeof(buf), "%llu%llu", x, x>>1);
	} while(0);

	if(pipe(fdin) < 0)		xerror("pipe");
	if(pipe(fdout) < 0)		xerror("pipe");
	if((child = fork()) < 0)	xerror("fork");
	if(child == 0) {
		signal(SIGCHLD, SIG_DFL);
		dup2(fdin[1], 1);  close(fdin[0]);  close(fdin[1]);
		dup2(fdout[0], 0); close(fdout[0]); close(fdout[1]);
		alarm(30);
		setup_filter();
		envvar(0);
	} else {
		int s;
		char *secret = strdup(buf);
		close(fdin[1]);
		close(fdout[0]);
		do if((s = read(fdin[0], buf, sizeof(buf))) > 0) {
			if(strncmp(buf, CHECKENV, s) != 0) break;
			if(check_envvar(secret) < 0) break;
			printf("Bingo!\n");
			write(fdout[1], "pass", 4);
			exit(0);
		} while(0);
		printf("No no no ...\n");
		write(fdout[1], "fail", 4);
	}
	return -1;
}

