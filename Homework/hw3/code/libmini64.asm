
%macro gensys 2
	global sys_%2:function
sys_%2:
	push	r10
	mov	r10, rcx
	mov	rax, %1
	syscall
	pop	r10
	ret
%endmacro

; RDI, RSI, RDX, RCX, R8, R9

extern	errno

	section .data

	section .text

	gensys   0, read
	gensys   1, write
	gensys   2, open
	gensys   3, close
	gensys   9, mmap
	gensys  10, mprotect
	gensys  11, munmap

	gensys	13, rt_sigaction
	gensys  14, rt_sigprocmask

	gensys  22, pipe
	gensys  32, dup
	gensys  33, dup2
	gensys  34, pause
	gensys  35, nanosleep

	gensys  37, alarm
	
	gensys  57, fork
	gensys  60, exit
	gensys  79, getcwd
	gensys  80, chdir
	gensys  82, rename
	gensys  83, mkdir
	gensys  84, rmdir
	gensys  85, creat
	gensys  86, link
	gensys  88, unlink
	gensys  89, readlink
	gensys  90, chmod
	gensys  92, chown
	gensys  95, umask
	gensys  96, gettimeofday
	gensys 102, getuid
	gensys 104, getgid
	gensys 105, setuid
	gensys 106, setgid
	gensys 107, geteuid
	gensys 108, getegid
	gensys 127, rt_sigpending

	global open:function

; setjmp
	global setjmp:function
setjmp:
	mov [rdi], rbx
	mov [rdi+1*8], rsp
	mov [rdi+2*8], rbp
	mov [rdi+3*8], r12
	mov [rdi+4*8], r13
	mov [rdi+5*8], r14
	mov [rdi+6*8], r15

	mov rax, [rsp]
	mov [rdi+7*8], rax

	push rcx

	; rt_sigprocmask(how, set, oldmask, sigsetsize)
	; rdi, rsi, rdx, rcx
	lea rdx, [rdi+8*8]
	mov rdi, 0x0
	mov rsi, 0x0 ; ignore value of rdi
	mov rcx, 8

	call sys_rt_sigprocmask
	pop rcx
	

	mov rax, 0x0
	ret

; longjmp
	global longjmp:function
longjmp:
	mov rbx, [rdi]
	mov rsp, [rdi+1*8]
	mov rbp, [rdi+2*8]
	mov r12, [rdi+3*8]
	mov r13, [rdi+4*8]
	mov r14, [rdi+5*8]
	mov r15, [rdi+6*8]

	pop rax
	mov rax, [rdi+7*8]
	push rax

	push rdi
	push rsi
	push rdx
	push rcx

	; rt_sigprocmask(how, set, oldmask, sigsetsize)
	; rdi, rsi, rdx, rcx
	lea rsi, [rdi+8*8]
	mov rdi, 0x2 ; SIG_SETMASK = 2
	mov rdx, 0x0
	mov rcx, 0x8

	call sys_rt_sigprocmask
	pop rcx
	pop rdx
	pop rsi
	pop rdi

	cmp rsi, 0x0 ; check if set is NULL
	jne longjmpOK
	mov rsi, 0x1
longjmpOK:
	mov rax, rsi
	ret
	
global sys_rt_sigreturn:function
sys_rt_sigreturn:
	mov rax, 15
	syscall
	ret

open:
	call	sys_open
	cmp	rax, 0
	jge	open_success	; no error :)
open_error:
	neg	rax
%ifdef NASM
	mov	rdi, [rel errno wrt ..gotpc]
%else
	mov	rdi, [rel errno wrt ..gotpcrel]
%endif
	mov	[rdi], rax	; errno = -rax
	mov	rax, -1
	jmp	open_quit
open_success:
%ifdef NASM
	mov	rdi, [rel errno wrt ..gotpc]
%else
	mov	rdi, [rel errno wrt ..gotpcrel]
%endif
	mov	QWORD [rdi], 0	; errno = 0
open_quit:
	ret

	global sleep:function
sleep:
	sub	rsp, 32		; allocate timespec * 2
	mov	[rsp], rdi		; req.tv_sec
	mov	QWORD [rsp+8], 0	; req.tv_nsec
	mov	rdi, rsp	; rdi = req @ rsp
	lea	rsi, [rsp+16]	; rsi = rem @ rsp+16
	call	sys_nanosleep
	cmp	rax, 0
	jge	sleep_quit	; no error :)
sleep_error:
	neg	rax
	cmp	rax, 4		; rax == EINTR?
	jne	sleep_failed
sleep_interrupted:
	lea	rsi, [rsp+16]
	mov	rax, [rsi]	; return rem.tv_sec
	jmp	sleep_quit
sleep_failed:
	mov	rax, 0		; return 0 on error
sleep_quit:
	add	rsp, 32
	ret

