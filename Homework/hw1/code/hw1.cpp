#include<stdio.h>
#include<stdlib.h>
#include<iostream>
#include<dirent.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<unistd.h>
#include<fcntl.h>
#include<errno.h>
#include<pwd.h>
#include<string.h>
#include<stdbool.h>
#include<regex.h>
#include<string>
#include<unordered_map>
#include<fstream>

#define MAX_LEN 1024

using namespace std;

struct pidInfo{
	char command[MAX_LEN];
	pid_t pid;
	string user = "";
	string fd = "";
	string type = "";
	string node;
	char name[MAX_LEN];
	string path = "";
	string filestatus = "";
	bool inFD = false;
};
bool c, t, f;
char *cmdregex;
char *nameregex;
char *typeregex;

void printHeader();
void printRecord(struct pidInfo *info);
void filterPrint(struct pidInfo *info);

int regexFind(char *s, char *pat);
int checkTYPE(string t);

string getType(mode_t m){
	if(S_ISREG(m)) return "REG";
	if(S_ISDIR(m)) return "DIR";
	if(S_ISCHR(m)) return "CHR";
	if(S_ISFIFO(m)) return "FIFO";
	if(S_ISSOCK(m)) return "SOCK";

	return "unknown";
}

string getPermission(string fdinfoPath){
	FILE *fdinfo;
	fdinfo = fopen(fdinfoPath.c_str(), "r");
	if(fdinfo != NULL){	
		char *line;
		size_t len = 0;
		if(getline(&line, &len, fdinfo) > 0){
			if(getline(&line, &len, fdinfo) > 0){
				int val;
				char title[MAX_LEN];
				
				sscanf(line, "%s %d", title, &val);
				//cout << "Successful: " << title  << " "<< val << endl;
				
				val &= O_ACCMODE;
			
				if(val == O_RDONLY){
					fclose(fdinfo);
					return "r";
				}
				if(val == O_WRONLY){
					fclose(fdinfo);
					return "w";
				}
				if(val == O_RDWR){
					fclose(fdinfo);
					return "u";
				}
			}
		}
		
	}
	return "";
}

void deleteCheck(struct pidInfo *info){
	if(strstr(info->filestatus.c_str(), "deleted") != NULL && !info->inFD){
		info->fd = "del";
		info->type = "unknown";
	}
}

void readName(string fdType, struct pidInfo *info, bool in_fd){
	string sPath = info->path;
	if(in_fd) sPath = sPath + "fd/";
	sPath = sPath + fdType;
	memset(info->name, 0, sizeof(info->name));
	char buf[MAX_LEN];
	int n = readlink(sPath.c_str(), buf, sizeof(buf)-1);
	struct stat typeStat;
	info->filestatus = "";
	if(errno == ENOENT) return;
	if(n < 0){
		strcpy(info->name, sPath.c_str());
		string err(strerror(errno));
		info->filestatus = " (readlink: "+err+")";
		info->type = "unknown";
		info->fd = fdType;
		info->node = "";
	}
	else{
		buf[n] = '\0';
		stat(sPath.c_str(), &typeStat);
		info->type = getType(typeStat.st_mode);
		info->fd = fdType;
		info->node = to_string(typeStat.st_ino);
		if(in_fd){
			info->inFD = true;
			if(strstr(buf, "deleted") != NULL){
				strncpy(info->name, buf, n-10);
				info->filestatus = " (deleted)";
				info->type = "unknown";
			}
			else strncpy(info->name, buf, n);
			lstat(sPath.c_str(), &typeStat);
			info->fd = info->fd+getPermission(info->path+"fdinfo/"+info->fd);
		}
		else{
			if(strstr(buf, "deleted") != NULL){
				strncpy(info->name, buf, n-10);
				info->filestatus = " (deleted)";
			}
			else strncpy(info->name, buf, n);
		}
	}
	if(c || f || t) filterPrint(info);
	else printRecord(info);
}

void readMem(struct pidInfo *info){
	int fd;
	string memPath = info->path + "maps";
	char buf[MAX_LEN];
	memset(info->name, 0, sizeof(info->name));
	size_t offset;
	char device[MAX_LEN], file[MAX_LEN], deleted[MAX_LEN];
	long int inode;
	FILE *maps;
	maps = fopen(memPath.c_str(), "r");
	info->node = "";
	info->filestatus = "";
	if(maps != NULL){
		char *line;
		size_t len = 0;
		unordered_map<long int, int> vis;
		while(getline(&line, &len, maps) > 0){
			memset(deleted, 0, sizeof(deleted));
			memset(file, 0, sizeof(file));
			if(sscanf(line, "%*x-%*x %*s %zx %5s %ld %s %s", &offset, device, &inode, file, deleted) < 3) continue;
			if(inode == 0 || !strcmp(device, "00:00")) continue;
			struct stat memStat;
			stat(file, &memStat);
				
			if(vis[inode] == 0){
				vis[inode] = 1;
				info->type = getType(memStat.st_mode);
				info->node = to_string(inode);
				strcpy(info->name, file);
				if(strstr(deleted, "deleted") != NULL) info->filestatus = " (deleted)";
				else info->filestatus = "";

				info->fd = "mem";

				if(c || f || t) filterPrint(info);
				else printRecord(info);
			}
		}
		fclose(maps);
	}
}

void readFd(struct pidInfo *info){
	int fd;
	DIR *dir;
	string fdPath = info->path + "fd/";
	dir = opendir(fdPath.c_str());
	memset(info->name, 0, sizeof(info->name));
	if(dir == NULL){
		info->fd = "NOFD";
		info->type = "";
		strcpy(info->name, info->path.c_str());
		strcat(info->name, "fd");
		string err(strerror(errno));
		info->filestatus = " (opendir: "+err+")";
		info->node = "";
		if(c || f || t) filterPrint(info);
		else printRecord(info);
	}
	else{
		struct dirent *ent;
		while((ent = readdir(dir))){
			if(!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
			info->node = "";
			readName(ent->d_name, info, 1);
		}
		closedir(dir);
	}
}

void readCmdline(struct pidInfo *info){
	int fd;
	string cmdPath = info->path + "comm";
	fd = open(cmdPath.c_str(), O_RDONLY);
	memset(info->command, 0, sizeof(info->command));
	if (fd < 0) return;
	
	char buf[MAX_LEN];
	int n = read(fd, buf, sizeof(buf));
	close(fd);
	if(n < 0) return;
	
	buf[n-1] = '\0';
	strncpy(info->command, buf, sizeof(buf));
}

void lsofInfo(pid_t pid){
	struct pidInfo info;
	struct stat pidstat;
	struct passwd *pwd;

	info.pid = pid;
	info.path = "/proc/"+to_string(info.pid)+"/";
	if(!stat(info.path.c_str(), &pidstat)){
		pwd = getpwuid(pidstat.st_uid);
		if(pwd != NULL) info.user = pwd->pw_name;
		else info.user = to_string((int)pidstat.st_uid);
	}
	else info.user = "unknown";
	readCmdline(&info);
	readName("cwd", &info, 0);
	readName("root", &info, 0);
	readName("exe", &info, 0);
	readMem(&info);
	readFd(&info);
}

void openProc(){
	DIR *proc = opendir("/proc");
	struct dirent *ent;
	long int pid;

	if(proc == NULL){
		perror("Cannot open /proc");
		exit(errno);
	}
	
	while(ent = readdir(proc)){
		if(!isdigit(*ent->d_name)) continue;
		
		pid = strtol(ent->d_name, NULL, 10);
		lsofInfo(pid);
	}
	closedir(proc);
}


int main(int argc, char *argv[]){
	int ch;
	c = false, t = false, f = false;

	while((ch = getopt(argc, argv, "c:t:f:")) != -1){
		switch(ch){
			case 'c':
				{
					c = true;
					cmdregex = optarg;
					break;
				}
			case 't':
				{
					t = true;
					if(strcmp(optarg, "REG") && strcmp(optarg, "CHR") && strcmp(optarg, "DIR") && strcmp(optarg, "FIFO") && strcmp(optarg, "SOCK") && strcmp(optarg, "unknown")){
						cout << "Invalid TYPE option.\n";
						return 0;
					}
					typeregex = optarg;
					break;
				}
			case 'f':
				{
					f = true;
					nameregex = optarg;
					break;
				}
			default:
				cout << "Usage: [sudo] ./hw1 [-c REGEX] [-t TYPE] [-f REGEX]\n"; 
				return 0;
		}
	}
	printHeader();
	openProc();
	
	return 0;
}

void printHeader(){
	printf("%-35s %-10s %-10s %-10s %-10s %-10s %-s\n", "COMMAND", "PID", "USER", "FD", "TYPE", "NODE", "NAME");
}

void printRecord(struct pidInfo *info){
	deleteCheck(info);
	printf("%-35s %-10d %-10s %-10s %-10s %-10s %-s\n", info->command, info->pid, info->user.c_str(), info->fd.c_str(), info->type.c_str(), info->node.c_str(), strcat(info->name, info->filestatus.c_str()));
}

int regexFind(char *s, char *pat){
	regex_t preg;
	int success = regcomp(&preg, pat, REG_EXTENDED);
	
	regmatch_t matchptr[1];
	const size_t nmatch = 1;
	int status = regexec(&preg, s, nmatch, matchptr, 0);
	regfree(&preg);
	return ((status == REG_NOMATCH)? 0:1);
}

void filterPrint(struct pidInfo *info){
	deleteCheck(info);
	if(c && f && t){
		bool toutput = strcmp(info->type.c_str(), typeregex);
		int freg = regexFind(info->name, nameregex);
		int creg = regexFind(info->command, cmdregex);
		
		if(creg && freg && toutput == 0) printRecord(info);
	}
	else if(c && f){
		int freg = regexFind(info->name, nameregex);
		int creg = regexFind(info->command, cmdregex);
		if(creg && freg) printRecord(info);
	}
	else if(f && t){
		bool toutput = strcmp(info->type.c_str(), typeregex);
		int freg = regexFind(info->name, nameregex);
		
		if(freg && toutput == 0) printRecord(info);
	}
	else if(c && t){
		bool toutput = strcmp(info->type.c_str(), typeregex);
		int creg = regexFind(info->command, cmdregex);
		if(creg && toutput == 0) printRecord(info);
	}
	else if(c){
		int creg = regexFind(info->command, cmdregex);
		if(creg) printRecord(info);
	}
	else if(t){
		if(strcmp(info->type.c_str(), typeregex) == 0) printRecord(info);
	}
	else if(f){
		int freg = regexFind(info->name, nameregex);
		if(freg) printRecord(info);
	}
}

