CXX = gcc
C_FLAGS = -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI

LD = ld
LD_FLAGS = -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -L. -L.. -lmini -o

START = start

YASM = yasm 
YASM_FLAGS = -f elf64 -DYASM -D__x86_64__ -DPIC 
LIBMINI64 = libmini64
LIBMINI = libmini
LIBMINI_CFLAG = -c -g -Wall -fno-stack-protector -fPIC -nostdlib


alarm1:
	$(YASM) $(YASM_FLAGS) $(LIBMINI64).asm -o $(LIBMINI64).o
	$(CXX) $(LIBMINI_CFLAG) $(LIBMINI).c
	$(LD) -shared -o $(LIBMINI).so $(LIBMINI64).o $(LIBMINI).o
	$(YASM)$(YASM_FLAGS) $(START).asm -o $(START).o
	$(CXX) $(C_FLAGS) $@.c
	$(LD) $(LD_FLAGS) $@ $@.o $(START).o
	rm $@.o $(LIBMINI64).o $(START).o

alarm2:
	$(YASM) $(YASM_FLAGS) $(LIBMINI64).asm -o $(LIBMINI64).o
	$(CXX) $(LIBMINI_CFLAG) $(LIBMINI).c
	$(LD) -shared -o $(LIBMINI).so $(LIBMINI64).o $(LIBMINI).o
	$(YASM)$(YASM_FLAGS) $(START).asm -o $(START).o
	$(CXX) $(C_FLAGS) $@.c
	$(LD) $(LD_FLAGS) $@ $@.o $(START).o
	rm $@.o	$(LIBMINI64).o $(START).o	

alarm3:
	$(YASM) $(YASM_FLAGS) $(LIBMINI64).asm -o $(LIBMINI64).o
	$(CXX) $(LIBMINI_CFLAG) $(LIBMINI).c
	$(LD) -shared -o $(LIBMINI).so $(LIBMINI64).o $(LIBMINI).o
	$(YASM)$(YASM_FLAGS) $(START).asm -o $(START).o
	$(CXX) $(C_FLAGS) $@.c
	$(LD) $(LD_FLAGS) $@ $@.o $(START).o
	rm $@.o $(LIBMINI64).o $(START).o

jmp1:
	$(YASM) $(YASM_FLAGS) $(LIBMINI64).asm -o $(LIBMINI64).o
	$(CXX) $(LIBMINI_CFLAG) $(LIBMINI).c
	$(LD) -shared -o $(LIBMINI).so $(LIBMINI64).o $(LIBMINI).o
	$(YASM)$(YASM_FLAGS) $(START).asm -o $(START).o
	$(CXX) $(C_FLAGS) $@.c
	$(LD) $(LD_FLAGS) $@ $@.o $(START).o
	rm $@.o $(LIBMINI64).o $(START).o

clean:
	rm *.o
