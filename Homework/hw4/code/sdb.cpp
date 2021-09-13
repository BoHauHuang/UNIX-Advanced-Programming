#include<iostream>
#include<string>
#include<vector>
#include<sstream>
#include<fstream>
#include<unordered_map>

#include<stdio.h>
#include<inttypes.h>
#include<capstone/capstone.h>
#include<unistd.h>
#include<string.h>
#include<sys/ptrace.h>
#include<sys/wait.h>
#include<sys/types.h>
#include<assert.h>
#include<sys/user.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>
#include <fcntl.h>

using namespace std;
#define MAX_LEN 1024

#define NLOADED 0x10    // 0001 0000
#define LOADED  0x20    // 0010 0000
#define RUNNING 0x40    // 0100 0000
#define QUIT    0x80    // 1000 0000

struct breakpoint {
    int id;
    unsigned long long addr;
    unsigned long code;
    bool valid;
};

#define PEEKSIZE        8

class instruction1 {
public:
        unsigned char bytes[16];
        int size;
        string opr, opnd;
};

static csh cshandle = 0;
static unordered_map<long long, instruction1> instructions;
vector<breakpoint> bplist;

Elf64_Ehdr *ehdr;
Elf64_Shdr *shdr;
char *elfp;
unsigned long long text_begin;
unsigned long long text_end;

string programPath = "";
string scriptPath = "";
FILE *ptr = NULL; 
int state = NLOADED;
int has_script = 0;
int not_exit = 1;
int bid = 0;
int textbase = 0;
int has_disasm = 0;
unsigned long long prevaddr = -1;
unsigned long long predismaddr = -1;
pid_t pid = 0;

struct user_regs_struct regs_struct;
vector<string> reglist = {"rax", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rdi", "rsi", "rbp", "rsp", "rip", "flags"};
unordered_map<string, unsigned int*> regs;

void help(){
	fprintf(stderr, "- break {instruction-address}: add a break point\n");
	fprintf(stderr, "- cont: continue execution\n");
	fprintf(stderr, "- delete {break-point-id}: remove a break point\n");
	fprintf(stderr, "- disasm addr: disassemble instructions in a file or a memory region\n");
	fprintf(stderr, "- dump addr [length]: dump memory content\n");
	fprintf(stderr, "- exit: terminate the debugger\n");
	fprintf(stderr, "- get reg: get a single value from a register\n");
	fprintf(stderr, "- getregs: show registers\n");
	fprintf(stderr, "- help: show this message\n");
	fprintf(stderr, "- list: list break points\n");
	fprintf(stderr, "- load {path/to/a/program}: load a program\n");
	fprintf(stderr, "- run: run the program\n");
	fprintf(stderr, "- vmmap: show memory layout\n");
	fprintf(stderr, "- set reg val: get a single value to a register\n");
	fprintf(stderr, "- si: step into instruction\n");
	fprintf(stderr, "- start: start the program and stop at the first instruction\n");
}

void errquit(const char *msg)
{
    perror(msg);
    exit(-1);
}

vector<string> split(const string &s, const char d = '\0') {
    vector<string> res;
    stringstream ss(s);
    string item;
    if (d) while (getline(ss, item, d)) res.push_back(item);
    else while (ss >> item) res.push_back(item);
    return res;
}

bool chkat(const auto &x, unsigned int at, bool p) {
    if (x.size() > at) return true;
    if (p) fprintf(stderr, "** missing argument.\n");
    return false;
}

unsigned char patch_byte(const unsigned long long addr, unsigned char c) {
    auto code = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
    ptrace(PTRACE_POKETEXT, pid, addr, (code & 0xffffffffffffff00) | (c & 0xff));
    return code & 0xff;
}

long long str2ll(const string &s) {
    if (s.find("0x") == 0 || s.find("0X") == 0) return stoll(s, NULL, 16);
    else if (s.find("0") == 0) return stoll(s, NULL, 8);
    else return stoll(s);
}

long long str2ull(const string &s) {
    if (s.find("0x") == 0 || s.find("0X") == 0) return stoull(s, NULL, 16);
    else if (s.find("0") == 0) return stoull(s, NULL, 8);
    else return stoull(s);
}

char UpperCase(char c){ return c^0x20; }

void myexit() {
    if (pid) kill(pid, SIGTERM);
    fprintf(stdout, "Bye.\n");
}

int is_bp(unsigned long long addr){
    for(int i = 0 ; i < bplist.size() ; i++){
        if(bplist[i].valid && bplist[i].addr == addr) return i;
    }
    return -1;
}

void load() {
    if(state != NLOADED) {
        fprintf(stderr, "** program %s already loaded\n", programPath.c_str());
        return;
    }
    
    if( access( programPath.c_str(), F_OK ) != 0 ){
        fprintf (stderr, "** program %s does not exist\n", programPath.c_str());
        return;
    }

    struct stat st;
    stat(programPath.c_str(), &st);
    int fd = open(programPath.c_str(), O_RDONLY);
    elfp = (char*)mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    ehdr = (Elf64_Ehdr*)elfp;
    shdr = (Elf64_Shdr *)(elfp + ehdr->e_shoff);
    int shnum = ehdr->e_shnum;

    Elf64_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
    char *const sh_strtab_p = elfp + sh_strtab->sh_offset;

    for (int i = 0; i < shnum; ++i) {
        //printf("%2d: %4d '%s'\n", i, shdr[i].sh_name, sh_strtab_p + shdr[i].sh_name);
        if(!strcmp(sh_strtab_p+shdr[i].sh_name, ".text")){
            text_begin = shdr[i].sh_addr;
            text_end = text_begin + shdr[i].sh_size;
            break;
        }
    }
    fprintf(stderr, "** program \'%s\' loaded. entry point 0x%lx\n", programPath.c_str(), ehdr->e_entry);
    state = LOADED;
    close(fd);
}

void start() {
    if (state != LOADED && state != RUNNING) {
        fprintf(stderr, "** no program loaded. \n");
        return;
    }
    if (pid) {
        fprintf(stderr, "** program %s running. \n", programPath.c_str());
        return;
    }

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "** fork error.\n");
        return;
    }
    else if (pid == 0) {    // child 
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            fprintf(stderr, "** ptrace error.\n");
        }
        char *argv[] = {NULL};
        execvp(programPath.c_str(), argv);
    }
    else { // parent 
        int status;
        waitpid(pid, &status, 0);

        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
        fprintf(stderr, "** pid %d\n", pid);
        state = RUNNING;
    }
}

void disasmSingleBP(unsigned long long addr){
    if(addr < text_begin || addr >= text_end){
        fprintf(stderr, "\n");
        return;
    }
    
    csh handle;
    cs_insn *insn;
    size_t count;
    unsigned char *codebyte;
    long code;

    int bp_idx = -1;
    if((bp_idx = is_bp(addr)) >= 0) code = bplist[bp_idx].code;
    else{
        fprintf(stderr, "\n");
        return;
    }

    codebyte = (unsigned char*)&code;

    if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK){
        fprintf(stderr, "\n");
        return;
    }

    count = cs_disasm(handle, codebyte, 8, addr, 0, &insn);

    if (count > 0) {
        fprintf(stderr, ":");
        int j = 0;
        for(j = 0; j < insn[0].size; j++){
            fprintf(stderr, " %2.2x", codebyte[j]);
        }
        while(j++ < 5){
            fprintf(stderr,"   ");
        }
        fprintf(stderr, "\t\t%s\t%s\n", insn[0].mnemonic, insn[0].op_str);
        addr += insn[0].size;

        cs_free(insn, count);
    } 

    cs_close(&handle);
}

void si(){
    if(state != RUNNING){
        fprintf(stderr, "** No program running.\n");
        return;
    }

    int wait_status;
    struct user_regs_struct siregs;
    int idx;
    unsigned long code;
    ptrace(PTRACE_GETREGS, pid, 0, &siregs);
    idx = is_bp(siregs.rip);

    code = ptrace(PTRACE_PEEKTEXT, pid, bplist[idx].addr, 0);
    if((code & 0x00000000000000ff) == 0xcc){
        code = (code & 0xffffffffffffff00) | (bplist[idx].code & 0x00000000000000ff);
        ptrace(PTRACE_POKETEXT, pid, siregs.rip, code);
        fprintf(stderr,"** breakpoint @\t%llx", siregs.rip);
        disasmSingleBP(siregs.rip);
        return;
    }

    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    waitpid(pid, &wait_status,0);

    if (WIFEXITED(wait_status)) {
        fprintf(stderr, "** child process %d terminiated normally (code %d)\n", pid, wait_status);
        pid = 0;
        state = LOADED;
        return;
    }
    
    code = ptrace(PTRACE_PEEKTEXT, pid, bplist[idx].addr, 0);
    bplist[idx].code = code;
    ptrace(PTRACE_POKETEXT, pid, bplist[idx].addr, (code & 0xffffffffffffff00) | 0xcc);

}

void cont() {
    if (state != RUNNING) {
        fprintf(stderr, "** no program running.\n");
        return;
    }
    int wait_status;
    struct user_regs_struct contreg;
    unsigned long contcode;
    ptrace(PTRACE_GETREGS, pid, 0, &contreg);
    int id = is_bp(contreg.rip);

    if(id >= 0){
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
        waitpid(pid, &wait_status, 0);

        contcode = ptrace(PTRACE_PEEKTEXT, pid, bplist[id].addr, 0);
        bplist[id].code = contcode;
        ptrace(PTRACE_PEEKTEXT, pid, bplist[id].addr, (contcode & 0xffffffffffffff00) | 0xcc);
        bplist[id].valid = 0;
    }
    
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, &wait_status, 0);

    if (WIFEXITED(wait_status)) {
        fprintf(stderr, "** child process %d terminiated normally (code %d)\n", pid, wait_status);
        pid = 0;
        state = LOADED;
        return;
    }
    
    struct user_regs_struct _regs;
    ptrace(PTRACE_GETREGS, pid, 0, &_regs);
    _regs.rip--;
    
    fprintf(stderr,"** breakpoint @\t%llx", _regs.rip);
    disasmSingleBP(_regs.rip);
        
    ptrace(PTRACE_SETREGS, pid, 0, &_regs);
}


void run() {
    if (state == RUNNING) {
        fprintf(stderr, "** program '%s' is already running.\n", programPath.c_str());
        cont();
    }
    else if (state == LOADED) {
        state = RUNNING;
        start();
        cont();
    }
    else {
        fprintf(stderr, "** No program loaded\n");
    }
}

void vmmap(){
    if (state != RUNNING) {
        fprintf(stderr, "** no program running.\n");
        return;
    }
    char procmap[MAX_LEN] = "";
    sprintf(procmap, "/proc/%d/maps", pid);
    FILE *mapfile = fopen(procmap, "r");
    if(mapfile == NULL){
        fprintf(stderr, "** no program running\n");
        return;
    }
    char *buf;
    size_t bufsize = 0;
    size_t offset;
    char permission[MAX_LEN], device[MAX_LEN], file[MAX_LEN], deleted[MAX_LEN];
    long int inode;
    unsigned int addrA, addrB;

    while(getline(&buf, &bufsize, mapfile) > 0){
        sscanf(buf,"%x-%x %s %zx %5s %ld %s", &addrA, &addrB, permission, &offset, device, &inode, file);
        fprintf(stderr, "%016x-%016x %s %-8ld %s\n", addrA, addrB, permission, inode, file);
    }
}

void get_regs(){
    ptrace(PTRACE_GETREGS, pid, NULL, &regs_struct);
    regs["rax"] = (unsigned int*) &regs_struct.rax;
    regs["rbx"] = (unsigned int*) &regs_struct.rbx;
    regs["rcx"] = (unsigned int*) &regs_struct.rcx;
    regs["rdx"] = (unsigned int*) &regs_struct.rdx;
    regs["rsp"] = (unsigned int*) &regs_struct.rsp;
    regs["rbp"] = (unsigned int*) &regs_struct.rbp;
    regs["rsi"] = (unsigned int*) &regs_struct.rsi;
    regs["rdi"] = (unsigned int*) &regs_struct.rdi;
    regs["rip"] = (unsigned int*) &regs_struct.rip;
    regs["r8"] = (unsigned int*) &regs_struct.r8;
    regs["r9"] = (unsigned int*) &regs_struct.r9;
    regs["r10"] = (unsigned int*) &regs_struct.r10;
    regs["r11"] = (unsigned int*) &regs_struct.r11;
    regs["r12"] = (unsigned int*) &regs_struct.r12;
    regs["r13"] = (unsigned int*) &regs_struct.r13;
    regs["r14"] = (unsigned int*) &regs_struct.r14;
    regs["r15"] = (unsigned int*) &regs_struct.r15;
    regs["flags"] = (unsigned int*) &regs_struct.eflags;
}

void print_all_regs(){
    fprintf(stderr, "RAX %-18x RBX %-18x RCX %-18x RDX %-18x\n", *regs["rax"], *regs["rbx"], *regs["rcx"], *regs["rdx"]);
    fprintf(stderr, "R8  %-18x R9  %-18x R10 %-18x R11 %-18x\n", *regs["r8"] , *regs["r9"] , *regs["r10"], *regs["r11"]);
    fprintf(stderr, "R12 %-18x R13 %-18x R14 %-18x R15 %-18x\n", *regs["r12"], *regs["r13"], *regs["r14"], *regs["r15"]);
    fprintf(stderr, "RDI %-18x RSI %-18x RBP %-18x RSP %-18x\n", *regs["rdi"], *regs["rsi"], *regs["rbp"], *regs["rsp"]);
    fprintf(stderr, "RIP %-18x FLAGS %016x\n", *regs["rip"], *regs["flags"]);
}

void getregs(){
    get_regs();
    print_all_regs();
}

string allLower(string r){
    string lr = "";
    for(auto x:r){
        lr += (x|0x20);
    }
    return lr;
}

void print_reg(string r){
    fprintf(stderr, "%s = %d (0x%x)\n", r.c_str(), *(int*)regs[r], *regs[r]);
}

void get(string r) {
    if (state != RUNNING) {
        fprintf(stderr, "** No program running.\n");
        return;
    }
    get_regs();
    string lr = allLower(r);

    bool valid_r = false;
    for(auto x:reglist){
        if(x==lr){
            valid_r = true;
            break;
        }
    }
    if(valid_r){
        print_reg(lr);
    }
    else{
        fprintf(stderr, "** %s is not a valid reg name.\n", r.c_str());
    }
}

void set(string r, long long val){
    if (state != RUNNING) {
        fprintf(stderr, "** No program running.\n");
        return;
    }
    get_regs();
    *regs[r] = (unsigned int)val;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs_struct);
    fprintf(stderr, "** set %s: %llx.\n", r.c_str(), val);
}

void bp(unsigned long long addr){
    if(state != RUNNING){
        fprintf(stderr, "** No program running.\n");
        return;
    }
    if(addr == 0){
        fprintf(stderr,"** Not a valid address\n");
        return;
    }

    unsigned long bpcode;
    bpcode = ptrace(PTRACE_PEEKTEXT, pid, addr,0);
    bplist.push_back({bid++, addr, bpcode, 1});
    ptrace(PTRACE_POKETEXT, pid, addr, (bpcode & 0xffffffffffffff00) | 0xcc);
}

void list(){
    for(int i = 0 ; i < bplist.size() ; i++){
        fprintf(stderr, "  %d: %llx\n", i, bplist[i].addr);
    }
}

void bpdelete(int idx){
    if(state != RUNNING){
        fprintf(stderr, "** No program running.\n");
        return;
    }
    if(idx > bplist.size()){
        fprintf(stderr, "** breakpoint index out of range.\n");
        return;
    }
    unsigned long code = ptrace(PTRACE_PEEKTEXT, pid, bplist[idx].addr, 0);
    code = (code & 0xffffffffffffff00) | (bplist[idx].code & 0x00000000000000ff);
    ptrace(PTRACE_POKETEXT, pid, bplist[idx].addr, code);

    bplist.erase(bplist.begin()+idx);

    fprintf(stderr, "** breakpoint %d deleted.\n", idx);
}

void dump(unsigned long long addr, long long dump_len = 80){
    if(state != RUNNING){
        fprintf(stderr, "** No program running.\n");
        return;
    }
    if(prevaddr == -1 && addr == -1){
        fprintf(stderr, "** No address given.\n");
        return;
    }

    long code1;
    long code2;
    unsigned char *ptr1 = (unsigned char*) &code1;
    unsigned char *ptr2 = (unsigned char*) &code2;
    for(int i = 0; i < dump_len; i+=16){
        code1 = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
        code2 = ptrace(PTRACE_PEEKTEXT, pid, addr+8, 0);
        fprintf(stderr,"      %llx: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x",
                addr,ptr1[0],ptr1[1],ptr1[2],ptr1[3],ptr1[4],ptr1[5],ptr1[6],ptr1[7],ptr2[0],ptr2[1],ptr2[2],ptr2[3],ptr2[4],ptr2[5],ptr2[6],ptr2[7]);
        for(int j = 0; j < 8; j++){
            if(!isprint(ptr1[j])) ptr1[j] = '.';
            if(!isprint(ptr2[j])) ptr2[j] = '.';
        }
        fprintf(stderr," |%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c|\n",
                ptr1[0],ptr1[1],ptr1[2],ptr1[3],ptr1[4],ptr1[5],ptr1[6],ptr1[7],ptr2[0],ptr2[1],ptr2[2],ptr2[3],ptr2[4],ptr2[5],ptr2[6],ptr2[7]);
        addr += 16;
    }
    prevaddr = addr;
}

void disasm(unsigned long long addr){
    if(state != RUNNING){
        fprintf(stderr, "** No program running.\n");
        return;
    }
    if(has_disasm == 0 && addr == -1){
        fprintf(stderr, "** no addr is given.\n");
        return;
    }
    if(addr < text_begin || addr >= text_end){
        fprintf(stdout,"** Address %llx is out of .text segment.\n", addr);
        return;
    }

    csh handle;
    cs_insn *insn;
    int ins_l = 10;
    size_t count;
    unsigned char *codebyte;
    long code;

    codebyte = (unsigned char*)&code;

    if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return;

    while(ins_l){
        if(addr < text_begin || addr >= text_end) break;
        int bp_idx = -1;
        if((bp_idx = is_bp(addr)) >= 0) code = bplist[bp_idx].code;
        else code = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);

        count = cs_disasm(handle, codebyte, 8, addr, 0, &insn);

        if (count > 0) {
            fprintf(stdout, "      %lx:", insn[0].address);
            int j = 0;
            for(j = 0; j < insn[0].size; j++){
                fprintf(stdout, " %2.2x", codebyte[j]);
            }
            while(j++ < 5){
                fprintf(stdout,"   ");
            }
            fprintf(stderr, "\t\t%s\t%s\n", insn[0].mnemonic, insn[0].op_str);
            addr += insn[0].size;
            ins_l--;
    
            cs_free(insn, count);
        } 
        else if(ins_l == 10){
            fprintf(stdout,"** wrong code.\n");
            break;
        }
    }
    cs_close(&handle);
    if(ins_l == 0){
        predismaddr = addr;
        has_disasm = 1;
    }
    return;
}

void parse_command(string s){
    vector<string> line = split(s);
    if (line.empty()) return;
    string cmd = line[0];
    
    if (cmd == "exit" || cmd == "q") {
        not_exit = 0;
        myexit();
        return;
    }
    else if (cmd == "help" || cmd == "h") {
        help();
    }
    else if (cmd == "load") {
        if (chkat(line, 1, true)) programPath = line[1];
        load();
    }
    else if (cmd == "start") {
        start();
    }
    else if (cmd == "cont" || cmd == "c") {
        cont();
    }
    else if (cmd == "run" || cmd == "r") {
        run();
    }
    else if (cmd == "vmmap" || cmd == "m") {
        vmmap();
    }
    else if (cmd == "getregs") {
        getregs();
    }
    else if (cmd == "get" || cmd == "g") {
        if (chkat(line, 1, true)) get(line[1]);
    }
    else if (cmd == "set" || cmd == "s") {
        if (chkat(line, 2, true)) set(line[1], str2ll(line[2]));
    }
    if (cmd == "break" || cmd == "b") {
        if (chkat(line, 1, true)) bp(str2ull(line[1]));
    }
    else if (cmd == "list" || cmd == "l") {
        list();
    }
    else if (cmd == "delete") {
        if (chkat(line, 1, true)) bpdelete(stoi(line[1]));
    }
    else if (cmd == "dump" || cmd == "x") {
        if (chkat(line, 1, false)){
            if (chkat(line, 2, false)) dump(str2ull(line[1]), str2ll(line[2]));
            else dump(str2ull(line[1]));
        }
        else dump(prevaddr);
    }
    else if (cmd == "si") {
        si();
    }
    else if (cmd == "disasm" || cmd == "d") {
        if (chkat(line, 1, false)) disasm(str2ull(line[1]));
        else disasm(predismaddr);
    }
}

int main(int argc, char *argv[]) {
    int opt;
    while( (opt = getopt(argc, argv, "s:") ) != -1 ){
        switch(opt){
            case 's':
                scriptPath = optarg;
                has_script = 1;
                break;
            default:
                fprintf(stdout,"usage: ./hw4 [-s script] [program]\n");
                exit(-1);
                break;
        }
    }

    if(optind < argc){
        programPath = argv[optind];
        load();
    }
    if(has_script){
        if( access( scriptPath.c_str(), F_OK ) != 0 ){
            fprintf (stderr, "** script %s does not exist\n", scriptPath.c_str());
            return 0;
        }
        ifstream fin(scriptPath.c_str());
        string s;
        while (getline(fin, s) && not_exit) {
            parse_command(s);
        }
        if(not_exit) fprintf(stdout, "Bye.\n");
    }
    else{
        string s;
        while (not_exit) {
            fprintf(stderr, "sdb> ");
            getline(cin, s);
            parse_command(s);
        }
    }
    return 0;
}
