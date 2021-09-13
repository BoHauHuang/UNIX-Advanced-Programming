#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<stdbool.h>
#include<string.h>
#include<dlfcn.h>
#include<sys/types.h>
#include<sys/param.h>
#include<stdarg.h>
#include<fcntl.h>
#include<errno.h>
#include<ctype.h>
#include<stdio_ext.h>
#include<limits.h>

#define LOGGER_PREFIX "[logger]"
#define LEN 1024

static FILE* output = NULL;
typedef char *(*getenv_t)(const char *name);

char* getFilename(int fd){
        if(fd < 0) return "";
	static char filename[LEN], fdPath[LEN];

	sprintf(fdPath, "/proc/self/fd/%d", fd);
	
        int ret = readlink(fdPath, filename, LEN);
	if(ret == -1) return "";
	filename[ret] = '\0';
        return filename;
}

typedef FILE* (*fopen_t)(const char *filename, const char *mode);
void setOutput(){
        getenv_t original_getenv = (getenv_t) dlsym(RTLD_NEXT, "getenv");
        char *loggerOutput = original_getenv("LOGGER_OUTPUT");

	if(output != NULL) return;
        if(!strcmp(loggerOutput, "stderr")){
		output = stderr;
	}
        else{
                fopen_t original_fopen = (fopen_t) dlsym(RTLD_NEXT, "fopen");
		output = original_fopen(loggerOutput, "ab");
        }
}

/*typedef int (*execvp_t)(const char *file, char *const argv[]);
int execvp(const char *file, char *const argv[]){
	setOutput();
	execvp_t original_execvp = (execvp_t) dlsym(RTLD_NEXT, "execvp");
	
	int ret = original_execvp(file, argv);
        return ret;
}*/

// chmod
typedef int (*chmod_t)(const char *path, mode_t mode);
int chmod(const char *path, mode_t mode){
        setOutput();
        chmod_t original_chmod = (chmod_t) dlsym(RTLD_NEXT, __func__);

        char *realPath = calloc(LEN, sizeof(char));
        realPath = realpath(path, realPath);

        int ret = original_chmod(path, mode);

        if(realPath != NULL) fprintf(output, "%s %s(\"%s\", %o) = %d\n", LOGGER_PREFIX, __func__, realPath, mode, ret);
        else fprintf(output, "%s %s(\"%s\", %o) = %d\n", LOGGER_PREFIX, __func__, path, mode, ret);
	free(realPath);
        return ret;
}

// chown
typedef int (*chown_t)(const char *path, uid_t owner, gid_t group);
int chown(const char *path, uid_t owner, gid_t group){
        setOutput();
        chown_t original_chown = (chown_t) dlsym(RTLD_NEXT, __func__);

        char *realPath = calloc(LEN, sizeof(char));
        realPath = realpath(path, realPath);

        int ret = original_chown(path, owner, group);

        if(realPath != NULL) fprintf(output, "%s %s(\"%s\", %d, %d) = %d\n", LOGGER_PREFIX, __func__, realPath, owner, group, ret);
        else fprintf(output, "%s %s(\"%s\", %d, %d) = %d\n", LOGGER_PREFIX, __func__, path, owner, group, ret);
	free(realPath);
        return ret;
}

// close (OK)
typedef int (*close_t)(int fd);
int close(int fd){
        const char* filename = getFilename(fd);
        close_t original_close = (close_t) dlsym(RTLD_NEXT, __func__);


        setOutput();
	int ret = 0;	
	if(fd == fileno(output)){
		int newstderr = dup(fileno(output));
		ret = original_close(newstderr);
	}
        else ret = original_close(fd);

        char *realPath = calloc(LEN, sizeof(char));
        realPath = realpath(filename, realPath);
        setOutput();

        if(realPath != NULL) fprintf(output, "%s %s(\"%s\") = %d\n", LOGGER_PREFIX, __func__, realPath, ret);
        else fprintf(output, "%s %s(\"%s\") = %d\n", LOGGER_PREFIX, __func__, filename, ret);
	fflush(output);
	free(realPath);
	
        return ret;
}

// creat
typedef int (*creat_t)(const char *pathname, mode_t mode);
int creat(const char *pathname, mode_t mode){
        setOutput();
        creat_t original_creat = (creat_t) dlsym(RTLD_NEXT, __func__);

        int ret = original_creat(pathname, mode);

        char *realPath = calloc(LEN, sizeof(char));
        realPath = realpath(pathname, realPath);

        if(realPath != NULL) fprintf(output, "%s %s(\"%s\", %o) = %d\n", LOGGER_PREFIX, __func__, realPath, mode, ret);
        else fprintf(output, "%s %s(\"%s\", %o) = %d\n", LOGGER_PREFIX, __func__, pathname, mode, ret);

        return ret;
}

// creat64
typedef int (*creat64_t)(const char *pathname, mode_t mode);
int creat64(const char *pathname, mode_t mode){
        setOutput();
        creat64_t original_creat64 = (creat64_t) dlsym(RTLD_NEXT, __func__);

        int ret = original_creat64(pathname, mode);

        char *realPath = calloc(LEN, sizeof(char));
        realPath = realpath(pathname, realPath);

        if(realPath != NULL) fprintf(output, "%s %s(\"%s\", %o) = %d\n", LOGGER_PREFIX, __func__, realPath, mode, ret);
        else fprintf(output, "%s %s(\"%s\", %o) = %d\n", LOGGER_PREFIX, __func__, pathname, mode, ret);

        return ret;
}

// fclose
typedef int (*fclose_t)(FILE* fp);
int fclose(FILE *fp){
        char *fname = getFilename(fileno(fp));
        fclose_t original_fclose = (fclose_t) dlsym(RTLD_NEXT, __func__);
	setOutput();
	int ret = 0;
	if(fileno(fp) == fileno(output)){
		int newstderr = dup(fileno(output));
		FILE *gg = fdopen(newstderr, "w");
		ret = original_fclose(gg);
	}
	else ret = original_fclose(fp);

  //      setOutput();
	char realPath[PATH_MAX];
	memset(realPath, 0, sizeof(realPath));
        char *ok = realpath((const char*)fname, realPath);
	
        if(ok) fprintf(output, "%s %s(\"%s\") = %d\n", LOGGER_PREFIX, __func__, realPath, ret);
        else fprintf(output, "%s %s(\"%s\") = %d\n", LOGGER_PREFIX, __func__, fname, ret);
        
	return ret;
}
// fopen (OK)
FILE *fopen(const char *filename, const char *mode){
        FILE* ret;
        fopen_t original_fopen = (fopen_t) dlsym(RTLD_NEXT, __func__);	
	ret = original_fopen(filename, mode);
	char realPath[PATH_MAX];
        memset(realPath, 0, sizeof(realPath));
	char *ok = realpath(filename, realPath);

        setOutput();
        if(ok) fprintf(output, "%s %s(\"%s\", \"%s\") = %p\n", LOGGER_PREFIX, __func__, realPath, mode, ret);
        else fprintf(output, "%s %s(\"%s\", \"%s\") = %p\n", LOGGER_PREFIX, __func__, filename, mode, ret);
	
        return ret;
}

// fopen64
typedef FILE* (*fopen64_t)(const char *filename, const char *mode);
FILE *fopen64(const char *filename, const char *mode){
        setOutput();
        fopen64_t original_fopen64 = (fopen64_t) dlsym(RTLD_NEXT, __func__);

        FILE* ret = original_fopen64(filename, mode);
	if(ret == NULL) return ret;
        char* realPath = calloc(LEN, sizeof(char));
        realPath = realpath(filename, realPath);

        if(realPath != NULL) fprintf(output, "%s %s(\"%s\", \"%s\") = %p\n", LOGGER_PREFIX, __func__, realPath, mode, ret);
        else fprintf(output, "%s %s(\"%s\", \"%s\") = %p\n", LOGGER_PREFIX, __func__, filename, mode, ret);

        return ret;
}

// fread
typedef size_t (*fread_t)(void *ptr, size_t size, size_t nmemb, FILE* fp);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE* fp){
        setOutput();
        fread_t original_fread = (fread_t) dlsym(RTLD_NEXT, __func__);

        int fno = fileno(fp);
        const char *fname = getFilename(fno);

        char* realPath = calloc(LEN, sizeof(char));
        realPath = realpath(fname, realPath);

        int ret = original_fread(ptr, size, nmemb, fp);

        if(realPath != NULL){
                fprintf(output, "%s %s(\"", LOGGER_PREFIX, __func__);

                char *c = (char*)ptr;
                char *dot = ".";
                int cnt = 0;
                while(cnt < 32 && cnt < ret){
                        if(isprint(c[cnt])) fprintf(output, "%c", c[cnt]);
			else fprintf(output, "%c", dot[0]);
                        cnt++;
                }

                fprintf(output, "\", %ld, %ld, \"%s\") = %d\n", size, nmemb, realPath, ret);
        }
        else{
                fprintf(output, "%s %s(\"", LOGGER_PREFIX, __func__);

                char *c = (char*)ptr;
                char *dot = ".";
                int cnt = 0;
                while(cnt < 32 && cnt < ret){
			if(isprint(c[cnt])) fprintf(output, "%c", c[cnt]);
                        else fprintf(output, "%c", dot[0]);
                        cnt++;
                }

                fprintf(output, "\", %ld, %ld, \"%s\") = %d\n", size, nmemb, fname, ret);

        }
	free(realPath);
        return ret;
}

// fwrite
typedef size_t (*fwrite_t)(const void *ptr, size_t size, size_t nmemb, FILE *fp);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *fp){
        setOutput();
        fwrite_t original_fwrite = (fwrite_t) dlsym(RTLD_NEXT, __func__);

        int fno = fileno(fp);
        const char *fname = getFilename(fno);

        char* realPath = calloc(LEN, sizeof(char));
        realPath = realpath(fname, realPath);

        int ret = original_fwrite(ptr, size, nmemb, fp);

        if(realPath != NULL){
                //fprintf(output, "%s %s(\"%s\", %ld, %ld, \"%s\") = %d\n", LOGGER_PREFIX, __func__, (char*)ptr, size, nmemb, realPath, ret);
                fprintf(output, "%s %s(\"", LOGGER_PREFIX, __func__);

                char *c = (char*)ptr;
                char *dot = ".";
                int cnt = 0;
                while(cnt < 32 && cnt < nmemb){
			if(isprint(c[cnt])) fprintf(output, "%c", c[cnt]);
                        else fprintf(output, "%c", dot[0]);
                        cnt++;
                }

                fprintf(output, "\", %ld, %ld, \"%s\") = %d\n", size, nmemb, realPath, ret);
        }
        else{
                //fprintf(output, "%s %s(\"%s\", %ld, %ld, \"%s\") = %d\n", LOGGER_PREFIX, __func__, (char*)ptr, size, nmemb, fname, ret);
                fprintf(output, "%s %s(\"", LOGGER_PREFIX, __func__);

                char *c = (char*)ptr;
                char *dot = ".";
                int cnt = 0;
                while(cnt < 32 && cnt < nmemb){
			if(isprint(c[cnt])) fprintf(output, "%c", c[cnt]);
                        else fprintf(output, "%c", dot[0]);
                        cnt++;
                }

                fprintf(output, "\", %ld, %ld, \"%s\") = %d\n", size, nmemb, fname, ret);
        }

        return ret;
}
// open (OK)
//typedef int (*open_t)(const char *pathname, int flags, mode_t mode);
typedef int (*open_t)(const char *pathname, int flags, ...);
//int open(const char *pathname, int flags, mode_t mode){
int open(const char *pathname, int flags, ...){
        setOutput();
        open_t original_open = (open_t) dlsym(RTLD_NEXT, __func__);

        int ret;
        mode_t mode = 0;

        if(__OPEN_NEEDS_MODE(flags)){
                va_list ap;
                va_start(ap, flags);
                mode = va_arg(ap, int);
                va_end(ap);
                ret = original_open(pathname, flags, mode);
        }
        else ret = original_open(pathname, flags);

        char* realPath = calloc(LEN, sizeof(char));
        realPath = realpath(pathname, realPath);

        if(realPath != NULL) fprintf(output, "%s %s(\"%s\", %o, %o) = %d\n", LOGGER_PREFIX, __func__, realPath, flags, mode, ret);
        else fprintf(output, "%s %s(\"%s\", %o, %o) = %d\n", LOGGER_PREFIX, __func__, pathname, flags, mode, ret);

        return ret;
}

// open64
typedef int (*open64_t)(const char *pathname, int flags, ...);
int open64(const char *pathname, int flags, ...){
        setOutput();
        open64_t original_open64 = (open64_t) dlsym(RTLD_NEXT, __func__);

        int ret;
        mode_t mode = 0;

        if(__OPEN_NEEDS_MODE(flags)){
                va_list ap;
                va_start(ap, flags);
                mode = va_arg(ap, int);
                va_end(ap);
                ret = original_open64(pathname, flags, mode);
        }
        else ret = original_open64(pathname, flags);

        char* realPath = calloc(LEN, sizeof(char));
        realPath = realpath(pathname, realPath);

        if(realPath != NULL) fprintf(output, "%s %s(\"%s\", %o, %o) = %d\n", LOGGER_PREFIX, __func__, realPath, flags, mode, ret);
        else fprintf(output, "%s %s(\"%s\", %o, %o) = %d\n", LOGGER_PREFIX, __func__, pathname, flags, mode, ret);

        return ret;
}

// read (OK)
typedef ssize_t (*read_t)(int fd, void *buf, size_t count);
ssize_t read(int fd, void *buf, size_t count){
        setOutput();
        read_t original_read = (read_t) dlsym(RTLD_NEXT, __func__);
        ssize_t ret = original_read(fd, buf, count);

        const char *filename = getFilename(fd);
        char* realPath = calloc(LEN, sizeof(char));
        realPath = realpath(filename, realPath);

        if(realPath != NULL){
                fprintf(output, "%s %s(\"%s\", \"", LOGGER_PREFIX, __func__, realPath);
                char *c = (char*)buf;
                char *dot = ".";
                int cnt = 0;
                while(cnt < 32 && cnt < ret){
			if(isprint(c[cnt])) fprintf(output, "%c", c[cnt]);
                        else fprintf(output, "%c", dot[0]);
                        cnt++;
                }
                fprintf(output, "\", %ld) = %ld\n", count, ret);
        }
        else{
                //fprintf(output, "%s %s(\"%s\", \"%s\", %ld) = %ld\n", LOGGER_PREFIX, __func__, filename, (char*)buf, count, ret);
                fprintf(output, "%s %s(\"%s\", \"", LOGGER_PREFIX, __func__, filename);
                char *c = (char*)buf;
                char *dot = ".";
                int cnt = 0;
                while(cnt < 32 && cnt < ret){
			if(isprint(c[cnt])) fprintf(output, "%c", c[cnt]);
			else fprintf(output, "%c", dot[0]);
                        cnt++;
                }
                fprintf(output, "\", %ld) = %ld\n", count, ret);

        }
	fflush(output);
        return ret;
}


// remove
typedef int (*remove_t)(const char *pathname);
int remove(const char *pathname){
        setOutput();
        remove_t original_remove = (remove_t) dlsym(RTLD_NEXT, __func__);

        char *realPath = calloc(LEN, sizeof(char));
        realPath = realpath(pathname, realPath);

        int ret = original_remove(realPath);
        if(realPath != NULL) fprintf(output, "%s %s(\"%s\") = %d\n", LOGGER_PREFIX, __func__, realPath, ret);
        else fprintf(output, "%s %s(\"%s\") = %d\n", LOGGER_PREFIX, __func__, pathname, ret);

        return ret;
}

// rename
typedef int (*rename_t)(const char *oldpath, const char *newpath);
int rename(const char *oldpath, const char *newpath){
        setOutput();
        rename_t original_rename = (rename_t) dlsym(RTLD_NEXT, __func__);

        char *realPath_old = calloc(LEN, sizeof(char));
        char *realPath_new = calloc(LEN, sizeof(char));

        realPath_old = realpath(oldpath, realPath_old);

        int ret = original_rename(oldpath, newpath);

        realPath_new = realpath(newpath, realPath_new);

        if(realPath_old == NULL && realPath_new == NULL) fprintf(output, "%s %s(\"%s\", \"%s\") = %d\n", LOGGER_PREFIX, __func__, oldpath, newpath, ret);
        else if(realPath_old == NULL) fprintf(output, "%s %s(\"%s\", \"%s\") = %d\n", LOGGER_PREFIX, __func__, oldpath, realPath_new, ret);
        else if(realPath_new == NULL) fprintf(output, "%s %s(\"%s\", \"%s\") = %d\n", LOGGER_PREFIX, __func__, realPath_old, newpath, ret);
        else fprintf(output, "%s %s(\"%s\", \"%s\") = %d\n", LOGGER_PREFIX, __func__, realPath_old, realPath_new, ret);

        return ret;
}

// tmpfile
typedef FILE *(*tmpfile_t)(void);
FILE *tmpfile(void){
        setOutput();
        tmpfile_t original_tmpfile = (tmpfile_t) dlsym(RTLD_NEXT, __func__);
        FILE *ret = original_tmpfile();

        fprintf(output, "%s %s() = %p\n", LOGGER_PREFIX, __func__, ret);

        return ret;
}

// tmpfile64
typedef FILE *(*tmpfile64_t)(void);
FILE *tmpfile64(void){
        setOutput();
        tmpfile64_t original_tmpfile64 = (tmpfile64_t) dlsym(RTLD_NEXT, __func__);
        FILE *ret = original_tmpfile64();

        fprintf(output, "%s %s() = %p\n", LOGGER_PREFIX, __func__, ret);

        return ret;
}

// write (OK)
typedef ssize_t (*write_t)(int fd, const void *buf, size_t nbyte);
ssize_t write(int fd, const void *buf, size_t nbyte){
        setOutput();
        write_t original_write = (write_t) dlsym(RTLD_NEXT, __func__);
        ssize_t ret = original_write(fd, buf, nbyte);

        const char *filename = getFilename(fd);
        char* realPath = calloc(LEN, sizeof(char));
        realPath = realpath(filename, realPath);

        if(realPath != NULL){
                fprintf(output, "%s %s(\"%s\", \"", LOGGER_PREFIX, __func__, realPath);
                char *c = (char*)buf;
                char *dot = ".";
                int cnt = 0;
                while(cnt < 32 && cnt < nbyte){
			if(isprint(c[cnt])) fprintf(output, "%c", c[cnt]);
                        else fprintf(output, "%c", dot[0]);
                        cnt++;
                }
                fprintf(output, "\", %ld) = %ld\n", nbyte, ret);
        }
        else{
                fprintf(output, "%s %s(\"%s\", \"", LOGGER_PREFIX, __func__, filename);
                char *c = (char*)buf;
                char *dot = ".";
                int cnt = 0;
                while(cnt < 32 && cnt < nbyte){
			if(isprint(c[cnt])) fprintf(output, "%c", c[cnt]);
                        else fprintf(output, "%c", dot[0]);
                        cnt++;
                }
                fprintf(output, "\", %ld) = %ld\n", nbyte, ret);
        }
        return ret;
}
