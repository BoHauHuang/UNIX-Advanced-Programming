#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<stdbool.h>
#include<string.h>

#define DEFAULT_SOPATH "./logger.so"
#define LEN 1024

_Bool setSopath = false, setOutput = false;
extern char** environ;

void usage(){
	fprintf(stderr, "usage: ./logger [-o file] [-p sopath] [--] cmd [cmd args ...]\n");
	fprintf(stderr, "    -p: set the path to logger.so, default = ./logger.so\n");
	fprintf(stderr, "    -o: print output to file, print to \"stderr\" if no file specified\n");
	fprintf(stderr, "    --: separate the arguments for logger and for the command\n");
}

int main(int argc, char *argv[]){
	char* soPath = calloc(LEN, sizeof(char));
	char* outputPath = calloc(LEN, sizeof(char));
	soPath = realpath(DEFAULT_SOPATH, soPath);
	outputPath = "stderr";

	int ch;
	while((ch = getopt(argc, argv, "o:p:")) != -1){
                switch(ch){
                        case 'o':
                                {
					setOutput = true;
					outputPath = optarg;

                                        break;
                                }
                        case 'p':
                                {
					setSopath = true;
					soPath = optarg;
					char* rsoPath = realpath(optarg, soPath);
					if(rsoPath != NULL) soPath = realpath(optarg, soPath);

                                        break;
                                }
                        default:
				usage();
                                return -1;
                }
        }
	
	if(argc <= optind){
		fprintf(stderr, "no command given.\n");
		return -1;
	}
	setenv("LD_PRELOAD", soPath, 1);
	setenv("LOGGER_OUTPUT", outputPath, 1);

	FILE* fp = fopen(outputPath, "w");
	if(fp) remove(outputPath);
	
	char *prefix_preload = "LD_PRELOAD=";
	size_t len = strlen(prefix_preload);
	size_t solen = strlen(soPath);
	char *preload = malloc(len+solen+1);

	strcpy(preload, prefix_preload);
	strcat(preload, soPath);

	environ[0] = preload;

	execvp(argv[optind], argv+optind);
	
	return 0;
}
