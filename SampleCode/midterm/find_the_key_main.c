/*
 * Exam problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <seccomp.h>
#include <sys/types.h>
#include <sys/wait.h>

extern void find_the_key();

#define	xerror(x)	{ perror(x); exit(-1); }

static void
setup_filter() {
	scmp_filter_ctx ctx;
	/* only the following syscalls are allowed:
	   brk chdir close fstat getdents mmap mprotect munmap openat read stat write exit exit_group */
	if((ctx = seccomp_init(SCMP_ACT_KILL)) == NULL) xerror("seccomp_init");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0)	xerror("seccomp_rule");
	if(seccomp_load(ctx) < 0) xerror("seccomp_load");
}

static pid_t child = 0;

void sigchld(int s) {
	if(child > 0 && waitpid(child, &s, 0) > 0) {
		if(WIFSIGNALED(s)) { printf("child terminated with signal = %d.\n", WTERMSIG(s)); exit(-1); }
		child = 0;
	}
}
void killchild()	{ if(child > 0) kill(child, SIGKILL); }
void sigterm(int s)	{ killchild(); exit(-1); }

int
main() {
	int fd[2];
	char buf[64];
	atexit(killchild);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	signal(SIGCHLD, sigchld);
	signal(SIGTERM, sigterm);
	signal(SIGINT, sigterm);
	if(pipe(fd) < 0)		xerror("pipe");
	if((child = fork()) < 0)	xerror("fork");
	if(child == 0) {
		signal(SIGCHLD, SIG_DFL);
		dup2(fd[1], 1);
		alarm(300);
		setup_filter();
		find_the_key();
	} else {
		int s;
		if((s = read(fd[0], buf, sizeof(buf))) > 0) {
			write(1, buf, s);
		}
	}
	return 0;
}

