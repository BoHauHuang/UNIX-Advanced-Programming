
guess:     file format elf64-x86-64


Disassembly of section .interp:

0000000000000238 <.interp>:
 238:	2f                   	(bad)  
 239:	6c                   	ins    BYTE PTR es:[rdi],dx
 23a:	69 62 36 34 2f 6c 64 	imul   esp,DWORD PTR [rdx+0x36],0x646c2f34
 241:	2d 6c 69 6e 75       	sub    eax,0x756e696c
 246:	78 2d                	js     275 <_init-0x50b>
 248:	78 38                	js     282 <_init-0x4fe>
 24a:	36 2d 36 34 2e 73    	ss sub eax,0x732e3436
 250:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 251:	2e 32 00             	xor    al,BYTE PTR cs:[rax]

Disassembly of section .note.ABI-tag:

0000000000000254 <.note.ABI-tag>:
 254:	04 00                	add    al,0x0
 256:	00 00                	add    BYTE PTR [rax],al
 258:	10 00                	adc    BYTE PTR [rax],al
 25a:	00 00                	add    BYTE PTR [rax],al
 25c:	01 00                	add    DWORD PTR [rax],eax
 25e:	00 00                	add    BYTE PTR [rax],al
 260:	47                   	rex.RXB
 261:	4e 55                	rex.WRX push rbp
 263:	00 00                	add    BYTE PTR [rax],al
 265:	00 00                	add    BYTE PTR [rax],al
 267:	00 03                	add    BYTE PTR [rbx],al
 269:	00 00                	add    BYTE PTR [rax],al
 26b:	00 02                	add    BYTE PTR [rdx],al
 26d:	00 00                	add    BYTE PTR [rax],al
 26f:	00 00                	add    BYTE PTR [rax],al
 271:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .note.gnu.build-id:

0000000000000274 <.note.gnu.build-id>:
 274:	04 00                	add    al,0x0
 276:	00 00                	add    BYTE PTR [rax],al
 278:	14 00                	adc    al,0x0
 27a:	00 00                	add    BYTE PTR [rax],al
 27c:	03 00                	add    eax,DWORD PTR [rax]
 27e:	00 00                	add    BYTE PTR [rax],al
 280:	47                   	rex.RXB
 281:	4e 55                	rex.WRX push rbp
 283:	00 63 91             	add    BYTE PTR [rbx-0x6f],ah
 286:	54                   	push   rsp
 287:	74 97                	je     220 <_init-0x560>
 289:	d2 d5                	rcl    ch,cl
 28b:	d4                   	(bad)  
 28c:	02 6c 2f 4b          	add    ch,BYTE PTR [rdi+rbp*1+0x4b]
 290:	38 de                	cmp    dh,bl
 292:	d8 a1 a3 e0 4d 65    	fsub   DWORD PTR [rcx+0x654de0a3]

Disassembly of section .gnu.hash:

0000000000000298 <.gnu.hash>:
 298:	02 00                	add    al,BYTE PTR [rax]
 29a:	00 00                	add    BYTE PTR [rax],al
 29c:	10 00                	adc    BYTE PTR [rax],al
 29e:	00 00                	add    BYTE PTR [rax],al
 2a0:	01 00                	add    DWORD PTR [rax],eax
 2a2:	00 00                	add    BYTE PTR [rax],al
 2a4:	06                   	(bad)  
 2a5:	00 00                	add    BYTE PTR [rax],al
 2a7:	00 00                	add    BYTE PTR [rax],al
 2a9:	00 20                	add    BYTE PTR [rax],ah
 2ab:	00 80 01 10 00 10    	add    BYTE PTR [rax+0x10001001],al
 2b1:	00 00                	add    BYTE PTR [rax],al
 2b3:	00 11                	add    BYTE PTR [rcx],dl
 2b5:	00 00                	add    BYTE PTR [rax],al
 2b7:	00 29                	add    BYTE PTR [rcx],ch
 2b9:	1d 8c 1c 67 55       	sbb    eax,0x55671c8c
 2be:	61                   	(bad)  
 2bf:	10                   	.byte 0x10

Disassembly of section .dynsym:

00000000000002c0 <.dynsym>:
	...
 2d8:	93                   	xchg   ebx,eax
 2d9:	00 00                	add    BYTE PTR [rax],al
 2db:	00 20                	add    BYTE PTR [rax],ah
	...
 2ed:	00 00                	add    BYTE PTR [rax],al
 2ef:	00 11                	add    BYTE PTR [rcx],dl
 2f1:	00 00                	add    BYTE PTR [rax],al
 2f3:	00 12                	add    BYTE PTR [rdx],dl
	...
 305:	00 00                	add    BYTE PTR [rax],al
 307:	00 32                	add    BYTE PTR [rdx],dh
 309:	00 00                	add    BYTE PTR [rax],al
 30b:	00 12                	add    BYTE PTR [rdx],dl
	...
 31d:	00 00                	add    BYTE PTR [rax],al
 31f:	00 1b                	add    BYTE PTR [rbx],bl
 321:	00 00                	add    BYTE PTR [rax],al
 323:	00 12                	add    BYTE PTR [rdx],dl
	...
 335:	00 00                	add    BYTE PTR [rax],al
 337:	00 39                	add    BYTE PTR [rcx],bh
 339:	00 00                	add    BYTE PTR [rax],al
 33b:	00 12                	add    BYTE PTR [rdx],dl
	...
 34d:	00 00                	add    BYTE PTR [rax],al
 34f:	00 6b 00             	add    BYTE PTR [rbx+0x0],ch
 352:	00 00                	add    BYTE PTR [rax],al
 354:	12 00                	adc    al,BYTE PTR [rax]
	...
 366:	00 00                	add    BYTE PTR [rax],al
 368:	0b 00                	or     eax,DWORD PTR [rax]
 36a:	00 00                	add    BYTE PTR [rax],al
 36c:	12 00                	adc    al,BYTE PTR [rax]
	...
 37e:	00 00                	add    BYTE PTR [rax],al
 380:	47 00 00             	rex.RXB add BYTE PTR [r8],r8b
 383:	00 12                	add    BYTE PTR [rdx],dl
	...
 395:	00 00                	add    BYTE PTR [rax],al
 397:	00 af 00 00 00 20    	add    BYTE PTR [rdi+0x20000000],ch
	...
 3ad:	00 00                	add    BYTE PTR [rax],al
 3af:	00 40 00             	add    BYTE PTR [rax+0x0],al
 3b2:	00 00                	add    BYTE PTR [rax],al
 3b4:	12 00                	adc    al,BYTE PTR [rax]
	...
 3c6:	00 00                	add    BYTE PTR [rax],al
 3c8:	16                   	(bad)  
 3c9:	00 00                	add    BYTE PTR [rax],al
 3cb:	00 12                	add    BYTE PTR [rdx],dl
	...
 3dd:	00 00                	add    BYTE PTR [rax],al
 3df:	00 63 00             	add    BYTE PTR [rbx+0x0],ah
 3e2:	00 00                	add    BYTE PTR [rax],al
 3e4:	12 00                	adc    al,BYTE PTR [rax]
	...
 3f6:	00 00                	add    BYTE PTR [rax],al
 3f8:	be 00 00 00 20       	mov    esi,0x20000000
	...
 40d:	00 00                	add    BYTE PTR [rax],al
 40f:	00 54 00 00          	add    BYTE PTR [rax+rax*1+0x0],dl
 413:	00 22                	add    BYTE PTR [rdx],ah
	...
 425:	00 00                	add    BYTE PTR [rax],al
 427:	00 0c 00             	add    BYTE PTR [rax+rax*1],cl
 42a:	00 00                	add    BYTE PTR [rax],al
 42c:	12 00                	adc    al,BYTE PTR [rax]
	...
 43e:	00 00                	add    BYTE PTR [rax],al
 440:	4d 00 00             	rex.WRB add BYTE PTR [r8],r8b
 443:	00 11                	add    BYTE PTR [rcx],dl
 445:	00 18                	add    BYTE PTR [rax],bl
 447:	00 10                	add    BYTE PTR [rax],dl
 449:	10 20                	adc    BYTE PTR [rax],ah
 44b:	00 00                	add    BYTE PTR [rax],al
 44d:	00 00                	add    BYTE PTR [rax],al
 44f:	00 08                	add    BYTE PTR [rax],cl
 451:	00 00                	add    BYTE PTR [rax],al
 453:	00 00                	add    BYTE PTR [rax],al
 455:	00 00                	add    BYTE PTR [rax],al
 457:	00 2c 00             	add    BYTE PTR [rax+rax*1],ch
 45a:	00 00                	add    BYTE PTR [rax],al
 45c:	11 00                	adc    DWORD PTR [rax],eax
 45e:	18 00                	sbb    BYTE PTR [rax],al
 460:	20 10                	and    BYTE PTR [rax],dl
 462:	20 00                	and    BYTE PTR [rax],al
 464:	00 00                	add    BYTE PTR [rax],al
 466:	00 00                	add    BYTE PTR [rax],al
 468:	08 00                	or     BYTE PTR [rax],al
 46a:	00 00                	add    BYTE PTR [rax],al
 46c:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .dynstr:

0000000000000470 <.dynstr>:
 470:	00 6c 69 62          	add    BYTE PTR [rcx+rbp*2+0x62],ch
 474:	63 2e                	movsxd ebp,DWORD PTR [rsi]
 476:	73 6f                	jae    4e7 <_init-0x299>
 478:	2e 36 00 73 72       	cs add BYTE PTR ss:[rbx+0x72],dh
 47d:	61                   	(bad)  
 47e:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 47f:	64 00 70 75          	add    BYTE PTR fs:[rax+0x75],dh
 483:	74 73                	je     4f8 <_init-0x288>
 485:	00 74 69 6d          	add    BYTE PTR [rcx+rbp*2+0x6d],dh
 489:	65 00 5f 5f          	add    BYTE PTR gs:[rdi+0x5f],bl
 48d:	73 74                	jae    503 <_init-0x27d>
 48f:	61                   	(bad)  
 490:	63 6b 5f             	movsxd ebp,DWORD PTR [rbx+0x5f]
 493:	63 68 6b             	movsxd ebp,DWORD PTR [rax+0x6b]
 496:	5f                   	pop    rdi
 497:	66 61                	data16 (bad) 
 499:	69 6c 00 73 74 64 69 	imul   ebp,DWORD PTR [rax+rax*1+0x73],0x6e696474
 4a0:	6e 
 4a1:	00 67 65             	add    BYTE PTR [rdi+0x65],ah
 4a4:	74 70                	je     516 <_init-0x26a>
 4a6:	69 64 00 70 72 69 6e 	imul   esp,DWORD PTR [rax+rax*1+0x70],0x746e6972
 4ad:	74 
 4ae:	66 00 73 74          	data16 add BYTE PTR [rbx+0x74],dh
 4b2:	72 74                	jb     528 <_init-0x258>
 4b4:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 4b5:	6c                   	ins    BYTE PTR es:[rdi],dx
 4b6:	00 66 67             	add    BYTE PTR [rsi+0x67],ah
 4b9:	65 74 73             	gs je  52f <_init-0x251>
 4bc:	00 73 74             	add    BYTE PTR [rbx+0x74],dh
 4bf:	64 6f                	outs   dx,DWORD PTR fs:[rsi]
 4c1:	75 74                	jne    537 <_init-0x249>
 4c3:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
 4c6:	63 78 61             	movsxd edi,DWORD PTR [rax+0x61]
 4c9:	5f                   	pop    rdi
 4ca:	66 69 6e 61 6c 69    	imul   bp,WORD PTR [rsi+0x61],0x696c
 4d0:	7a 65                	jp     537 <_init-0x249>
 4d2:	00 73 65             	add    BYTE PTR [rbx+0x65],dh
 4d5:	74 76                	je     54d <_init-0x233>
 4d7:	62                   	(bad)  
 4d8:	75 66                	jne    540 <_init-0x240>
 4da:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
 4dd:	6c                   	ins    BYTE PTR es:[rdi],dx
 4de:	69 62 63 5f 73 74 61 	imul   esp,DWORD PTR [rdx+0x63],0x6174735f
 4e5:	72 74                	jb     55b <_init-0x225>
 4e7:	5f                   	pop    rdi
 4e8:	6d                   	ins    DWORD PTR es:[rdi],dx
 4e9:	61                   	(bad)  
 4ea:	69 6e 00 47 4c 49 42 	imul   ebp,DWORD PTR [rsi+0x0],0x42494c47
 4f1:	43 5f                	rex.XB pop r15
 4f3:	32 2e                	xor    ch,BYTE PTR [rsi]
 4f5:	34 00                	xor    al,0x0
 4f7:	47                   	rex.RXB
 4f8:	4c                   	rex.WR
 4f9:	49                   	rex.WB
 4fa:	42                   	rex.X
 4fb:	43 5f                	rex.XB pop r15
 4fd:	32 2e                	xor    ch,BYTE PTR [rsi]
 4ff:	32 2e                	xor    ch,BYTE PTR [rsi]
 501:	35 00 5f 49 54       	xor    eax,0x54495f00
 506:	4d 5f                	rex.WRB pop r15
 508:	64 65 72 65          	fs gs jb 571 <_init-0x20f>
 50c:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
 513:	4d 
 514:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
 516:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 517:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 518:	65 54                	gs push rsp
 51a:	61                   	(bad)  
 51b:	62                   	(bad)  
 51c:	6c                   	ins    BYTE PTR es:[rdi],dx
 51d:	65 00 5f 5f          	add    BYTE PTR gs:[rdi+0x5f],bl
 521:	67 6d                	ins    DWORD PTR es:[edi],dx
 523:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 524:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 525:	5f                   	pop    rdi
 526:	73 74                	jae    59c <_init-0x1e4>
 528:	61                   	(bad)  
 529:	72 74                	jb     59f <_init-0x1e1>
 52b:	5f                   	pop    rdi
 52c:	5f                   	pop    rdi
 52d:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
 530:	54                   	push   rsp
 531:	4d 5f                	rex.WRB pop r15
 533:	72 65                	jb     59a <_init-0x1e6>
 535:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
 53c:	4d 
 53d:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
 53f:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 540:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 541:	65 54                	gs push rsp
 543:	61                   	(bad)  
 544:	62                   	.byte 0x62
 545:	6c                   	ins    BYTE PTR es:[rdi],dx
 546:	65                   	gs
	...

Disassembly of section .gnu.version:

0000000000000548 <.gnu.version>:
 548:	00 00                	add    BYTE PTR [rax],al
 54a:	00 00                	add    BYTE PTR [rax],al
 54c:	02 00                	add    al,BYTE PTR [rax]
 54e:	02 00                	add    al,BYTE PTR [rax]
 550:	03 00                	add    eax,DWORD PTR [rax]
 552:	02 00                	add    al,BYTE PTR [rax]
 554:	02 00                	add    al,BYTE PTR [rax]
 556:	02 00                	add    al,BYTE PTR [rax]
 558:	02 00                	add    al,BYTE PTR [rax]
 55a:	00 00                	add    BYTE PTR [rax],al
 55c:	02 00                	add    al,BYTE PTR [rax]
 55e:	02 00                	add    al,BYTE PTR [rax]
 560:	02 00                	add    al,BYTE PTR [rax]
 562:	00 00                	add    BYTE PTR [rax],al
 564:	02 00                	add    al,BYTE PTR [rax]
 566:	02 00                	add    al,BYTE PTR [rax]
 568:	02 00                	add    al,BYTE PTR [rax]
 56a:	02 00                	add    al,BYTE PTR [rax]

Disassembly of section .gnu.version_r:

0000000000000570 <.gnu.version_r>:
 570:	01 00                	add    DWORD PTR [rax],eax
 572:	02 00                	add    al,BYTE PTR [rax]
 574:	01 00                	add    DWORD PTR [rax],eax
 576:	00 00                	add    BYTE PTR [rax],al
 578:	10 00                	adc    BYTE PTR [rax],al
 57a:	00 00                	add    BYTE PTR [rax],al
 57c:	00 00                	add    BYTE PTR [rax],al
 57e:	00 00                	add    BYTE PTR [rax],al
 580:	14 69                	adc    al,0x69
 582:	69 0d 00 00 03 00 7d 	imul   ecx,DWORD PTR [rip+0x30000],0x7d        # 3058c <__FRAME_END__+0x2f8f0>
 589:	00 00 00 
 58c:	10 00                	adc    BYTE PTR [rax],al
 58e:	00 00                	add    BYTE PTR [rax],al
 590:	75 1a                	jne    5ac <_init-0x1d4>
 592:	69 09 00 00 02 00    	imul   ecx,DWORD PTR [rcx],0x20000
 598:	87 00                	xchg   DWORD PTR [rax],eax
 59a:	00 00                	add    BYTE PTR [rax],al
 59c:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .rela.dyn:

00000000000005a0 <.rela.dyn>:
 5a0:	70 0d                	jo     5af <_init-0x1d1>
 5a2:	20 00                	and    BYTE PTR [rax],al
 5a4:	00 00                	add    BYTE PTR [rax],al
 5a6:	00 00                	add    BYTE PTR [rax],al
 5a8:	08 00                	or     BYTE PTR [rax],al
 5aa:	00 00                	add    BYTE PTR [rax],al
 5ac:	00 00                	add    BYTE PTR [rax],al
 5ae:	00 00                	add    BYTE PTR [rax],al
 5b0:	60                   	(bad)  
 5b1:	09 00                	or     DWORD PTR [rax],eax
 5b3:	00 00                	add    BYTE PTR [rax],al
 5b5:	00 00                	add    BYTE PTR [rax],al
 5b7:	00 78 0d             	add    BYTE PTR [rax+0xd],bh
 5ba:	20 00                	and    BYTE PTR [rax],al
 5bc:	00 00                	add    BYTE PTR [rax],al
 5be:	00 00                	add    BYTE PTR [rax],al
 5c0:	08 00                	or     BYTE PTR [rax],al
 5c2:	00 00                	add    BYTE PTR [rax],al
 5c4:	00 00                	add    BYTE PTR [rax],al
 5c6:	00 00                	add    BYTE PTR [rax],al
 5c8:	20 09                	and    BYTE PTR [rcx],cl
 5ca:	00 00                	add    BYTE PTR [rax],al
 5cc:	00 00                	add    BYTE PTR [rax],al
 5ce:	00 00                	add    BYTE PTR [rax],al
 5d0:	08 10                	or     BYTE PTR [rax],dl
 5d2:	20 00                	and    BYTE PTR [rax],al
 5d4:	00 00                	add    BYTE PTR [rax],al
 5d6:	00 00                	add    BYTE PTR [rax],al
 5d8:	08 00                	or     BYTE PTR [rax],al
 5da:	00 00                	add    BYTE PTR [rax],al
 5dc:	00 00                	add    BYTE PTR [rax],al
 5de:	00 00                	add    BYTE PTR [rax],al
 5e0:	08 10                	or     BYTE PTR [rax],dl
 5e2:	20 00                	and    BYTE PTR [rax],al
 5e4:	00 00                	add    BYTE PTR [rax],al
 5e6:	00 00                	add    BYTE PTR [rax],al
 5e8:	d8 0f                	fmul   DWORD PTR [rdi]
 5ea:	20 00                	and    BYTE PTR [rax],al
 5ec:	00 00                	add    BYTE PTR [rax],al
 5ee:	00 00                	add    BYTE PTR [rax],al
 5f0:	06                   	(bad)  
 5f1:	00 00                	add    BYTE PTR [rax],al
 5f3:	00 01                	add    BYTE PTR [rcx],al
	...
 5fd:	00 00                	add    BYTE PTR [rax],al
 5ff:	00 e0                	add    al,ah
 601:	0f 20 00             	mov    rax,cr0
 604:	00 00                	add    BYTE PTR [rax],al
 606:	00 00                	add    BYTE PTR [rax],al
 608:	06                   	(bad)  
 609:	00 00                	add    BYTE PTR [rax],al
 60b:	00 06                	add    BYTE PTR [rsi],al
	...
 615:	00 00                	add    BYTE PTR [rax],al
 617:	00 e8                	add    al,ch
 619:	0f 20 00             	mov    rax,cr0
 61c:	00 00                	add    BYTE PTR [rax],al
 61e:	00 00                	add    BYTE PTR [rax],al
 620:	06                   	(bad)  
 621:	00 00                	add    BYTE PTR [rax],al
 623:	00 09                	add    BYTE PTR [rcx],cl
	...
 62d:	00 00                	add    BYTE PTR [rax],al
 62f:	00 f0                	add    al,dh
 631:	0f 20 00             	mov    rax,cr0
 634:	00 00                	add    BYTE PTR [rax],al
 636:	00 00                	add    BYTE PTR [rax],al
 638:	06                   	(bad)  
 639:	00 00                	add    BYTE PTR [rax],al
 63b:	00 0d 00 00 00 00    	add    BYTE PTR [rip+0x0],cl        # 641 <_init-0x13f>
 641:	00 00                	add    BYTE PTR [rax],al
 643:	00 00                	add    BYTE PTR [rax],al
 645:	00 00                	add    BYTE PTR [rax],al
 647:	00 f8                	add    al,bh
 649:	0f 20 00             	mov    rax,cr0
 64c:	00 00                	add    BYTE PTR [rax],al
 64e:	00 00                	add    BYTE PTR [rax],al
 650:	06                   	(bad)  
 651:	00 00                	add    BYTE PTR [rax],al
 653:	00 0e                	add    BYTE PTR [rsi],cl
	...
 65d:	00 00                	add    BYTE PTR [rax],al
 65f:	00 10                	add    BYTE PTR [rax],dl
 661:	10 20                	adc    BYTE PTR [rax],ah
 663:	00 00                	add    BYTE PTR [rax],al
 665:	00 00                	add    BYTE PTR [rax],al
 667:	00 05 00 00 00 10    	add    BYTE PTR [rip+0x10000000],al        # 1000066d <_end+0xfdff63d>
	...
 675:	00 00                	add    BYTE PTR [rax],al
 677:	00 20                	add    BYTE PTR [rax],ah
 679:	10 20                	adc    BYTE PTR [rax],ah
 67b:	00 00                	add    BYTE PTR [rax],al
 67d:	00 00                	add    BYTE PTR [rax],al
 67f:	00 05 00 00 00 11    	add    BYTE PTR [rip+0x11000000],al        # 11000685 <_end+0x10dff655>
	...

Disassembly of section .rela.plt:

0000000000000690 <.rela.plt>:
 690:	88 0f                	mov    BYTE PTR [rdi],cl
 692:	20 00                	and    BYTE PTR [rax],al
 694:	00 00                	add    BYTE PTR [rax],al
 696:	00 00                	add    BYTE PTR [rax],al
 698:	07                   	(bad)  
 699:	00 00                	add    BYTE PTR [rax],al
 69b:	00 02                	add    BYTE PTR [rdx],al
	...
 6a5:	00 00                	add    BYTE PTR [rax],al
 6a7:	00 90 0f 20 00 00    	add    BYTE PTR [rax+0x200f],dl
 6ad:	00 00                	add    BYTE PTR [rax],al
 6af:	00 07                	add    BYTE PTR [rdi],al
 6b1:	00 00                	add    BYTE PTR [rax],al
 6b3:	00 03                	add    BYTE PTR [rbx],al
	...
 6bd:	00 00                	add    BYTE PTR [rax],al
 6bf:	00 98 0f 20 00 00    	add    BYTE PTR [rax+0x200f],bl
 6c5:	00 00                	add    BYTE PTR [rax],al
 6c7:	00 07                	add    BYTE PTR [rdi],al
 6c9:	00 00                	add    BYTE PTR [rax],al
 6cb:	00 04 00             	add    BYTE PTR [rax+rax*1],al
	...
 6d6:	00 00                	add    BYTE PTR [rax],al
 6d8:	a0 0f 20 00 00 00 00 	movabs al,ds:0x70000000000200f
 6df:	00 07 
 6e1:	00 00                	add    BYTE PTR [rax],al
 6e3:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 6e9 <_init-0x97>
 6e9:	00 00                	add    BYTE PTR [rax],al
 6eb:	00 00                	add    BYTE PTR [rax],al
 6ed:	00 00                	add    BYTE PTR [rax],al
 6ef:	00 a8 0f 20 00 00    	add    BYTE PTR [rax+0x200f],ch
 6f5:	00 00                	add    BYTE PTR [rax],al
 6f7:	00 07                	add    BYTE PTR [rdi],al
 6f9:	00 00                	add    BYTE PTR [rax],al
 6fb:	00 07                	add    BYTE PTR [rdi],al
	...
 705:	00 00                	add    BYTE PTR [rax],al
 707:	00 b0 0f 20 00 00    	add    BYTE PTR [rax+0x200f],dh
 70d:	00 00                	add    BYTE PTR [rax],al
 70f:	00 07                	add    BYTE PTR [rdi],al
 711:	00 00                	add    BYTE PTR [rax],al
 713:	00 08                	add    BYTE PTR [rax],cl
	...
 71d:	00 00                	add    BYTE PTR [rax],al
 71f:	00 b8 0f 20 00 00    	add    BYTE PTR [rax+0x200f],bh
 725:	00 00                	add    BYTE PTR [rax],al
 727:	00 07                	add    BYTE PTR [rdi],al
 729:	00 00                	add    BYTE PTR [rax],al
 72b:	00 0a                	add    BYTE PTR [rdx],cl
	...
 735:	00 00                	add    BYTE PTR [rax],al
 737:	00 c0                	add    al,al
 739:	0f 20 00             	mov    rax,cr0
 73c:	00 00                	add    BYTE PTR [rax],al
 73e:	00 00                	add    BYTE PTR [rax],al
 740:	07                   	(bad)  
 741:	00 00                	add    BYTE PTR [rax],al
 743:	00 0b                	add    BYTE PTR [rbx],cl
	...
 74d:	00 00                	add    BYTE PTR [rax],al
 74f:	00 c8                	add    al,cl
 751:	0f 20 00             	mov    rax,cr0
 754:	00 00                	add    BYTE PTR [rax],al
 756:	00 00                	add    BYTE PTR [rax],al
 758:	07                   	(bad)  
 759:	00 00                	add    BYTE PTR [rax],al
 75b:	00 0c 00             	add    BYTE PTR [rax+rax*1],cl
	...
 766:	00 00                	add    BYTE PTR [rax],al
 768:	d0 0f                	ror    BYTE PTR [rdi],1
 76a:	20 00                	and    BYTE PTR [rax],al
 76c:	00 00                	add    BYTE PTR [rax],al
 76e:	00 00                	add    BYTE PTR [rax],al
 770:	07                   	(bad)  
 771:	00 00                	add    BYTE PTR [rax],al
 773:	00 0f                	add    BYTE PTR [rdi],cl
	...

Disassembly of section .init:

0000000000000780 <_init>:
 780:	48 83 ec 08          	sub    rsp,0x8
 784:	48 8b 05 5d 08 20 00 	mov    rax,QWORD PTR [rip+0x20085d]        # 200fe8 <__gmon_start__>
 78b:	48 85 c0             	test   rax,rax
 78e:	74 02                	je     792 <_init+0x12>
 790:	ff d0                	call   rax
 792:	48 83 c4 08          	add    rsp,0x8
 796:	c3                   	ret    

Disassembly of section .plt:

00000000000007a0 <.plt>:
 7a0:	ff 35 d2 07 20 00    	push   QWORD PTR [rip+0x2007d2]        # 200f78 <_GLOBAL_OFFSET_TABLE_+0x8>
 7a6:	ff 25 d4 07 20 00    	jmp    QWORD PTR [rip+0x2007d4]        # 200f80 <_GLOBAL_OFFSET_TABLE_+0x10>
 7ac:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

00000000000007b0 <puts@plt>:
 7b0:	ff 25 d2 07 20 00    	jmp    QWORD PTR [rip+0x2007d2]        # 200f88 <puts@GLIBC_2.2.5>
 7b6:	68 00 00 00 00       	push   0x0
 7bb:	e9 e0 ff ff ff       	jmp    7a0 <.plt>

00000000000007c0 <getpid@plt>:
 7c0:	ff 25 ca 07 20 00    	jmp    QWORD PTR [rip+0x2007ca]        # 200f90 <getpid@GLIBC_2.2.5>
 7c6:	68 01 00 00 00       	push   0x1
 7cb:	e9 d0 ff ff ff       	jmp    7a0 <.plt>

00000000000007d0 <__stack_chk_fail@plt>:
 7d0:	ff 25 c2 07 20 00    	jmp    QWORD PTR [rip+0x2007c2]        # 200f98 <__stack_chk_fail@GLIBC_2.4>
 7d6:	68 02 00 00 00       	push   0x2
 7db:	e9 c0 ff ff ff       	jmp    7a0 <.plt>

00000000000007e0 <printf@plt>:
 7e0:	ff 25 ba 07 20 00    	jmp    QWORD PTR [rip+0x2007ba]        # 200fa0 <printf@GLIBC_2.2.5>
 7e6:	68 03 00 00 00       	push   0x3
 7eb:	e9 b0 ff ff ff       	jmp    7a0 <.plt>

00000000000007f0 <srand@plt>:
 7f0:	ff 25 b2 07 20 00    	jmp    QWORD PTR [rip+0x2007b2]        # 200fa8 <srand@GLIBC_2.2.5>
 7f6:	68 04 00 00 00       	push   0x4
 7fb:	e9 a0 ff ff ff       	jmp    7a0 <.plt>

0000000000000800 <fgets@plt>:
 800:	ff 25 aa 07 20 00    	jmp    QWORD PTR [rip+0x2007aa]        # 200fb0 <fgets@GLIBC_2.2.5>
 806:	68 05 00 00 00       	push   0x5
 80b:	e9 90 ff ff ff       	jmp    7a0 <.plt>

0000000000000810 <strtol@plt>:
 810:	ff 25 a2 07 20 00    	jmp    QWORD PTR [rip+0x2007a2]        # 200fb8 <strtol@GLIBC_2.2.5>
 816:	68 06 00 00 00       	push   0x6
 81b:	e9 80 ff ff ff       	jmp    7a0 <.plt>

0000000000000820 <time@plt>:
 820:	ff 25 9a 07 20 00    	jmp    QWORD PTR [rip+0x20079a]        # 200fc0 <time@GLIBC_2.2.5>
 826:	68 07 00 00 00       	push   0x7
 82b:	e9 70 ff ff ff       	jmp    7a0 <.plt>

0000000000000830 <setvbuf@plt>:
 830:	ff 25 92 07 20 00    	jmp    QWORD PTR [rip+0x200792]        # 200fc8 <setvbuf@GLIBC_2.2.5>
 836:	68 08 00 00 00       	push   0x8
 83b:	e9 60 ff ff ff       	jmp    7a0 <.plt>

0000000000000840 <rand@plt>:
 840:	ff 25 8a 07 20 00    	jmp    QWORD PTR [rip+0x20078a]        # 200fd0 <rand@GLIBC_2.2.5>
 846:	68 09 00 00 00       	push   0x9
 84b:	e9 50 ff ff ff       	jmp    7a0 <.plt>

Disassembly of section .plt.got:

0000000000000850 <__cxa_finalize@plt>:
 850:	ff 25 a2 07 20 00    	jmp    QWORD PTR [rip+0x2007a2]        # 200ff8 <__cxa_finalize@GLIBC_2.2.5>
 856:	66 90                	xchg   ax,ax

Disassembly of section .text:

0000000000000860 <_start>:
 860:	31 ed                	xor    ebp,ebp
 862:	49 89 d1             	mov    r9,rdx
 865:	5e                   	pop    rsi
 866:	48 89 e2             	mov    rdx,rsp
 869:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
 86d:	50                   	push   rax
 86e:	54                   	push   rsp
 86f:	4c 8d 05 8a 02 00 00 	lea    r8,[rip+0x28a]        # b00 <__libc_csu_fini>
 876:	48 8d 0d 13 02 00 00 	lea    rcx,[rip+0x213]        # a90 <__libc_csu_init>
 87d:	48 8d 3d e6 00 00 00 	lea    rdi,[rip+0xe6]        # 96a <main>
 884:	ff 15 56 07 20 00    	call   QWORD PTR [rip+0x200756]        # 200fe0 <__libc_start_main@GLIBC_2.2.5>
 88a:	f4                   	hlt    
 88b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000000890 <deregister_tm_clones>:
 890:	48 8d 3d 79 07 20 00 	lea    rdi,[rip+0x200779]        # 201010 <stdout@@GLIBC_2.2.5>
 897:	55                   	push   rbp
 898:	48 8d 05 71 07 20 00 	lea    rax,[rip+0x200771]        # 201010 <stdout@@GLIBC_2.2.5>
 89f:	48 39 f8             	cmp    rax,rdi
 8a2:	48 89 e5             	mov    rbp,rsp
 8a5:	74 19                	je     8c0 <deregister_tm_clones+0x30>
 8a7:	48 8b 05 2a 07 20 00 	mov    rax,QWORD PTR [rip+0x20072a]        # 200fd8 <_ITM_deregisterTMCloneTable>
 8ae:	48 85 c0             	test   rax,rax
 8b1:	74 0d                	je     8c0 <deregister_tm_clones+0x30>
 8b3:	5d                   	pop    rbp
 8b4:	ff e0                	jmp    rax
 8b6:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
 8bd:	00 00 00 
 8c0:	5d                   	pop    rbp
 8c1:	c3                   	ret    
 8c2:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
 8c6:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
 8cd:	00 00 00 

00000000000008d0 <register_tm_clones>:
 8d0:	48 8d 3d 39 07 20 00 	lea    rdi,[rip+0x200739]        # 201010 <stdout@@GLIBC_2.2.5>
 8d7:	48 8d 35 32 07 20 00 	lea    rsi,[rip+0x200732]        # 201010 <stdout@@GLIBC_2.2.5>
 8de:	55                   	push   rbp
 8df:	48 29 fe             	sub    rsi,rdi
 8e2:	48 89 e5             	mov    rbp,rsp
 8e5:	48 c1 fe 03          	sar    rsi,0x3
 8e9:	48 89 f0             	mov    rax,rsi
 8ec:	48 c1 e8 3f          	shr    rax,0x3f
 8f0:	48 01 c6             	add    rsi,rax
 8f3:	48 d1 fe             	sar    rsi,1
 8f6:	74 18                	je     910 <register_tm_clones+0x40>
 8f8:	48 8b 05 f1 06 20 00 	mov    rax,QWORD PTR [rip+0x2006f1]        # 200ff0 <_ITM_registerTMCloneTable>
 8ff:	48 85 c0             	test   rax,rax
 902:	74 0c                	je     910 <register_tm_clones+0x40>
 904:	5d                   	pop    rbp
 905:	ff e0                	jmp    rax
 907:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
 90e:	00 00 
 910:	5d                   	pop    rbp
 911:	c3                   	ret    
 912:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
 916:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
 91d:	00 00 00 

0000000000000920 <__do_global_dtors_aux>:
 920:	80 3d 01 07 20 00 00 	cmp    BYTE PTR [rip+0x200701],0x0        # 201028 <completed.7698>
 927:	75 2f                	jne    958 <__do_global_dtors_aux+0x38>
 929:	48 83 3d c7 06 20 00 	cmp    QWORD PTR [rip+0x2006c7],0x0        # 200ff8 <__cxa_finalize@GLIBC_2.2.5>
 930:	00 
 931:	55                   	push   rbp
 932:	48 89 e5             	mov    rbp,rsp
 935:	74 0c                	je     943 <__do_global_dtors_aux+0x23>
 937:	48 8b 3d ca 06 20 00 	mov    rdi,QWORD PTR [rip+0x2006ca]        # 201008 <__dso_handle>
 93e:	e8 0d ff ff ff       	call   850 <__cxa_finalize@plt>
 943:	e8 48 ff ff ff       	call   890 <deregister_tm_clones>
 948:	c6 05 d9 06 20 00 01 	mov    BYTE PTR [rip+0x2006d9],0x1        # 201028 <completed.7698>
 94f:	5d                   	pop    rbp
 950:	c3                   	ret    
 951:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
 958:	f3 c3                	repz ret 
 95a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000000960 <frame_dummy>:
 960:	55                   	push   rbp
 961:	48 89 e5             	mov    rbp,rsp
 964:	5d                   	pop    rbp
 965:	e9 66 ff ff ff       	jmp    8d0 <register_tm_clones>

000000000000096a <main>:
 96a:	55                   	push   rbp
 96b:	48 89 e5             	mov    rbp,rsp
 96e:	53                   	push   rbx
 96f:	48 83 ec 38          	sub    rsp,0x38
 973:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
 97a:	00 00 
 97c:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
 980:	31 c0                	xor    eax,eax
 982:	48 8b 05 87 06 20 00 	mov    rax,QWORD PTR [rip+0x200687]        # 201010 <stdout@@GLIBC_2.2.5>
 989:	b9 00 00 00 00       	mov    ecx,0x0
 98e:	ba 02 00 00 00       	mov    edx,0x2
 993:	be 00 00 00 00       	mov    esi,0x0
 998:	48 89 c7             	mov    rdi,rax
 99b:	e8 90 fe ff ff       	call   830 <setvbuf@plt>
 9a0:	bf 00 00 00 00       	mov    edi,0x0
 9a5:	e8 76 fe ff ff       	call   820 <time@plt>
 9aa:	89 c3                	mov    ebx,eax
 9ac:	e8 0f fe ff ff       	call   7c0 <getpid@plt>
 9b1:	31 d8                	xor    eax,ebx
 9b3:	89 c7                	mov    edi,eax
 9b5:	e8 36 fe ff ff       	call   7f0 <srand@plt>
 9ba:	e8 81 fe ff ff       	call   840 <rand@plt>
 9bf:	89 c1                	mov    ecx,eax
 9c1:	ba ad 8b db 68       	mov    edx,0x68db8bad
 9c6:	89 c8                	mov    eax,ecx
 9c8:	f7 ea                	imul   edx
 9ca:	c1 fa 0c             	sar    edx,0xc
 9cd:	89 c8                	mov    eax,ecx
 9cf:	c1 f8 1f             	sar    eax,0x1f
 9d2:	29 c2                	sub    edx,eax
 9d4:	89 d0                	mov    eax,edx
 9d6:	69 c0 10 27 00 00    	imul   eax,eax,0x2710
 9dc:	29 c1                	sub    ecx,eax
 9de:	89 c8                	mov    eax,ecx
 9e0:	89 45 e0             	mov    DWORD PTR [rbp-0x20],eax
 9e3:	48 8d 3d 2a 01 00 00 	lea    rdi,[rip+0x12a]        # b14 <_IO_stdin_used+0x4>
 9ea:	b8 00 00 00 00       	mov    eax,0x0
 9ef:	e8 ec fd ff ff       	call   7e0 <printf@plt>
 9f4:	48 8b 15 25 06 20 00 	mov    rdx,QWORD PTR [rip+0x200625]        # 201020 <stdin@@GLIBC_2.2.5>
 9fb:	48 8d 45 d0          	lea    rax,[rbp-0x30]
 9ff:	be 14 00 00 00       	mov    esi,0x14
 a04:	48 89 c7             	mov    rdi,rax
 a07:	e8 f4 fd ff ff       	call   800 <fgets@plt>
 a0c:	48 85 c0             	test   rax,rax
 a0f:	74 51                	je     a62 <main+0xf8>
 a11:	48 8d 45 d0          	lea    rax,[rbp-0x30]
 a15:	ba 00 00 00 00       	mov    edx,0x0
 a1a:	be 00 00 00 00       	mov    esi,0x0
 a1f:	48 89 c7             	mov    rdi,rax
 a22:	e8 e9 fd ff ff       	call   810 <strtol@plt>
 a27:	89 45 cc             	mov    DWORD PTR [rbp-0x34],eax
 a2a:	8b 45 cc             	mov    eax,DWORD PTR [rbp-0x34]
 a2d:	89 c6                	mov    esi,eax
 a2f:	48 8d 3d f1 00 00 00 	lea    rdi,[rip+0xf1]        # b27 <_IO_stdin_used+0x17>
 a36:	b8 00 00 00 00       	mov    eax,0x0
 a3b:	e8 a0 fd ff ff       	call   7e0 <printf@plt>
 a40:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
 a43:	39 45 cc             	cmp    DWORD PTR [rbp-0x34],eax
 a46:	75 0e                	jne    a56 <main+0xec>
 a48:	48 8d 3d ea 00 00 00 	lea    rdi,[rip+0xea]        # b39 <_IO_stdin_used+0x29>
 a4f:	e8 5c fd ff ff       	call   7b0 <puts@plt>
 a54:	eb 0c                	jmp    a62 <main+0xf8>
 a56:	48 8d 3d e3 00 00 00 	lea    rdi,[rip+0xe3]        # b40 <_IO_stdin_used+0x30>
 a5d:	e8 4e fd ff ff       	call   7b0 <puts@plt>
 a62:	b8 00 00 00 00       	mov    eax,0x0
 a67:	48 8b 5d e8          	mov    rbx,QWORD PTR [rbp-0x18]
 a6b:	64 48 33 1c 25 28 00 	xor    rbx,QWORD PTR fs:0x28
 a72:	00 00 
 a74:	74 05                	je     a7b <main+0x111>
 a76:	e8 55 fd ff ff       	call   7d0 <__stack_chk_fail@plt>
 a7b:	48 83 c4 38          	add    rsp,0x38
 a7f:	5b                   	pop    rbx
 a80:	5d                   	pop    rbp
 a81:	c3                   	ret    
 a82:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
 a89:	00 00 00 
 a8c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000000a90 <__libc_csu_init>:
 a90:	41 57                	push   r15
 a92:	41 56                	push   r14
 a94:	49 89 d7             	mov    r15,rdx
 a97:	41 55                	push   r13
 a99:	41 54                	push   r12
 a9b:	4c 8d 25 ce 02 20 00 	lea    r12,[rip+0x2002ce]        # 200d70 <__frame_dummy_init_array_entry>
 aa2:	55                   	push   rbp
 aa3:	48 8d 2d ce 02 20 00 	lea    rbp,[rip+0x2002ce]        # 200d78 <__init_array_end>
 aaa:	53                   	push   rbx
 aab:	41 89 fd             	mov    r13d,edi
 aae:	49 89 f6             	mov    r14,rsi
 ab1:	4c 29 e5             	sub    rbp,r12
 ab4:	48 83 ec 08          	sub    rsp,0x8
 ab8:	48 c1 fd 03          	sar    rbp,0x3
 abc:	e8 bf fc ff ff       	call   780 <_init>
 ac1:	48 85 ed             	test   rbp,rbp
 ac4:	74 20                	je     ae6 <__libc_csu_init+0x56>
 ac6:	31 db                	xor    ebx,ebx
 ac8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
 acf:	00 
 ad0:	4c 89 fa             	mov    rdx,r15
 ad3:	4c 89 f6             	mov    rsi,r14
 ad6:	44 89 ef             	mov    edi,r13d
 ad9:	41 ff 14 dc          	call   QWORD PTR [r12+rbx*8]
 add:	48 83 c3 01          	add    rbx,0x1
 ae1:	48 39 dd             	cmp    rbp,rbx
 ae4:	75 ea                	jne    ad0 <__libc_csu_init+0x40>
 ae6:	48 83 c4 08          	add    rsp,0x8
 aea:	5b                   	pop    rbx
 aeb:	5d                   	pop    rbp
 aec:	41 5c                	pop    r12
 aee:	41 5d                	pop    r13
 af0:	41 5e                	pop    r14
 af2:	41 5f                	pop    r15
 af4:	c3                   	ret    
 af5:	90                   	nop
 af6:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
 afd:	00 00 00 

0000000000000b00 <__libc_csu_fini>:
 b00:	f3 c3                	repz ret 

Disassembly of section .fini:

0000000000000b04 <_fini>:
 b04:	48 83 ec 08          	sub    rsp,0x8
 b08:	48 83 c4 08          	add    rsp,0x8
 b0c:	c3                   	ret    

Disassembly of section .rodata:

0000000000000b10 <_IO_stdin_used>:
 b10:	01 00                	add    DWORD PTR [rax],eax
 b12:	02 00                	add    al,BYTE PTR [rax]
 b14:	47 75 65             	rex.RXB jne b7c <__GNU_EH_FRAME_HDR+0x2c>
 b17:	73 73                	jae    b8c <__GNU_EH_FRAME_HDR+0x3c>
 b19:	20 74 68 65          	and    BYTE PTR [rax+rbp*2+0x65],dh
 b1d:	20 6e 75             	and    BYTE PTR [rsi+0x75],ch
 b20:	6d                   	ins    DWORD PTR es:[rdi],dx
 b21:	62                   	(bad)  
 b22:	65 72 3a             	gs jb  b5f <__GNU_EH_FRAME_HDR+0xf>
 b25:	20 00                	and    BYTE PTR [rax],al
 b27:	59                   	pop    rcx
 b28:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 b29:	75 72                	jne    b9d <__GNU_EH_FRAME_HDR+0x4d>
 b2b:	20 67 75             	and    BYTE PTR [rdi+0x75],ah
 b2e:	65 73 73             	gs jae ba4 <__GNU_EH_FRAME_HDR+0x54>
 b31:	20 69 73             	and    BYTE PTR [rcx+0x73],ch
 b34:	20 25 64 0a 00 42    	and    BYTE PTR [rip+0x42000a64],ah        # 4200159e <_end+0x41e0056e>
 b3a:	69 6e 67 6f 21 00 4e 	imul   ebp,DWORD PTR [rsi+0x67],0x4e00216f
 b41:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 b42:	20 6e 6f             	and    BYTE PTR [rsi+0x6f],ch
 b45:	20 6e 6f             	and    BYTE PTR [rsi+0x6f],ch
 b48:	20 2e                	and    BYTE PTR [rsi],ch
 b4a:	2e                   	cs
 b4b:	2e                   	cs
	...

Disassembly of section .eh_frame_hdr:

0000000000000b50 <__GNU_EH_FRAME_HDR>:
 b50:	01 1b                	add    DWORD PTR [rbx],ebx
 b52:	03 3b                	add    edi,DWORD PTR [rbx]
 b54:	3c 00                	cmp    al,0x0
 b56:	00 00                	add    BYTE PTR [rax],al
 b58:	06                   	(bad)  
 b59:	00 00                	add    BYTE PTR [rax],al
 b5b:	00 50 fc             	add    BYTE PTR [rax-0x4],dl
 b5e:	ff                   	(bad)  
 b5f:	ff 88 00 00 00 00    	dec    DWORD PTR [rax+0x0]
 b65:	fd                   	std    
 b66:	ff                   	(bad)  
 b67:	ff b0 00 00 00 10    	push   QWORD PTR [rax+0x10000000]
 b6d:	fd                   	std    
 b6e:	ff                   	(bad)  
 b6f:	ff 58 00             	call   FWORD PTR [rax+0x0]
 b72:	00 00                	add    BYTE PTR [rax],al
 b74:	1a fe                	sbb    bh,dh
 b76:	ff                   	(bad)  
 b77:	ff c8                	dec    eax
 b79:	00 00                	add    BYTE PTR [rax],al
 b7b:	00 40 ff             	add    BYTE PTR [rax-0x1],al
 b7e:	ff                   	(bad)  
 b7f:	ff f0                	push   rax
 b81:	00 00                	add    BYTE PTR [rax],al
 b83:	00 b0 ff ff ff 38    	add    BYTE PTR [rax+0x38ffffff],dh
 b89:	01 00                	add    DWORD PTR [rax],eax
	...

Disassembly of section .eh_frame:

0000000000000b90 <__FRAME_END__-0x10c>:
 b90:	14 00                	adc    al,0x0
 b92:	00 00                	add    BYTE PTR [rax],al
 b94:	00 00                	add    BYTE PTR [rax],al
 b96:	00 00                	add    BYTE PTR [rax],al
 b98:	01 7a 52             	add    DWORD PTR [rdx+0x52],edi
 b9b:	00 01                	add    BYTE PTR [rcx],al
 b9d:	78 10                	js     baf <__GNU_EH_FRAME_HDR+0x5f>
 b9f:	01 1b                	add    DWORD PTR [rbx],ebx
 ba1:	0c 07                	or     al,0x7
 ba3:	08 90 01 07 10 14    	or     BYTE PTR [rax+0x14100701],dl
 ba9:	00 00                	add    BYTE PTR [rax],al
 bab:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
 bae:	00 00                	add    BYTE PTR [rax],al
 bb0:	b0 fc                	mov    al,0xfc
 bb2:	ff                   	(bad)  
 bb3:	ff 2b                	jmp    FWORD PTR [rbx]
	...
 bbd:	00 00                	add    BYTE PTR [rax],al
 bbf:	00 14 00             	add    BYTE PTR [rax+rax*1],dl
 bc2:	00 00                	add    BYTE PTR [rax],al
 bc4:	00 00                	add    BYTE PTR [rax],al
 bc6:	00 00                	add    BYTE PTR [rax],al
 bc8:	01 7a 52             	add    DWORD PTR [rdx+0x52],edi
 bcb:	00 01                	add    BYTE PTR [rcx],al
 bcd:	78 10                	js     bdf <__GNU_EH_FRAME_HDR+0x8f>
 bcf:	01 1b                	add    DWORD PTR [rbx],ebx
 bd1:	0c 07                	or     al,0x7
 bd3:	08 90 01 00 00 24    	or     BYTE PTR [rax+0x24000001],dl
 bd9:	00 00                	add    BYTE PTR [rax],al
 bdb:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
 bde:	00 00                	add    BYTE PTR [rax],al
 be0:	c0 fb ff             	sar    bl,0xff
 be3:	ff b0 00 00 00 00    	push   QWORD PTR [rax+0x0]
 be9:	0e                   	(bad)  
 bea:	10 46 0e             	adc    BYTE PTR [rsi+0xe],al
 bed:	18 4a 0f             	sbb    BYTE PTR [rdx+0xf],cl
 bf0:	0b 77 08             	or     esi,DWORD PTR [rdi+0x8]
 bf3:	80 00 3f             	add    BYTE PTR [rax],0x3f
 bf6:	1a 3b                	sbb    bh,BYTE PTR [rbx]
 bf8:	2a 33                	sub    dh,BYTE PTR [rbx]
 bfa:	24 22                	and    al,0x22
 bfc:	00 00                	add    BYTE PTR [rax],al
 bfe:	00 00                	add    BYTE PTR [rax],al
 c00:	14 00                	adc    al,0x0
 c02:	00 00                	add    BYTE PTR [rax],al
 c04:	44 00 00             	add    BYTE PTR [rax],r8b
 c07:	00 48 fc             	add    BYTE PTR [rax-0x4],cl
 c0a:	ff                   	(bad)  
 c0b:	ff 08                	dec    DWORD PTR [rax]
	...
 c15:	00 00                	add    BYTE PTR [rax],al
 c17:	00 24 00             	add    BYTE PTR [rax+rax*1],ah
 c1a:	00 00                	add    BYTE PTR [rax],al
 c1c:	5c                   	pop    rsp
 c1d:	00 00                	add    BYTE PTR [rax],al
 c1f:	00 4a fd             	add    BYTE PTR [rdx-0x3],cl
 c22:	ff                   	(bad)  
 c23:	ff 18                	call   FWORD PTR [rax]
 c25:	01 00                	add    DWORD PTR [rax],eax
 c27:	00 00                	add    BYTE PTR [rax],al
 c29:	41 0e                	rex.B (bad) 
 c2b:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
 c31:	45 83 03 03          	rex.RB add DWORD PTR [r11],0x3
 c35:	0e                   	(bad)  
 c36:	01 0c 07             	add    DWORD PTR [rdi+rax*1],ecx
 c39:	08 00                	or     BYTE PTR [rax],al
 c3b:	00 00                	add    BYTE PTR [rax],al
 c3d:	00 00                	add    BYTE PTR [rax],al
 c3f:	00 44 00 00          	add    BYTE PTR [rax+rax*1+0x0],al
 c43:	00 84 00 00 00 48 fe 	add    BYTE PTR [rax+rax*1-0x1b80000],al
 c4a:	ff                   	(bad)  
 c4b:	ff 65 00             	jmp    QWORD PTR [rbp+0x0]
 c4e:	00 00                	add    BYTE PTR [rax],al
 c50:	00 42 0e             	add    BYTE PTR [rdx+0xe],al
 c53:	10 8f 02 42 0e 18    	adc    BYTE PTR [rdi+0x180e4202],cl
 c59:	8e 03                	mov    es,WORD PTR [rbx]
 c5b:	45 0e                	rex.RB (bad) 
 c5d:	20 8d 04 42 0e 28    	and    BYTE PTR [rbp+0x280e4204],cl
 c63:	8c 05 48 0e 30 86    	mov    WORD PTR [rip+0xffffffff86300e48],es        # ffffffff86301ab1 <_end+0xffffffff86100a81>
 c69:	06                   	(bad)  
 c6a:	48 0e                	rex.W (bad) 
 c6c:	38 83 07 4d 0e 40    	cmp    BYTE PTR [rbx+0x400e4d07],al
 c72:	72 0e                	jb     c82 <__GNU_EH_FRAME_HDR+0x132>
 c74:	38 41 0e             	cmp    BYTE PTR [rcx+0xe],al
 c77:	30 41 0e             	xor    BYTE PTR [rcx+0xe],al
 c7a:	28 42 0e             	sub    BYTE PTR [rdx+0xe],al
 c7d:	20 42 0e             	and    BYTE PTR [rdx+0xe],al
 c80:	18 42 0e             	sbb    BYTE PTR [rdx+0xe],al
 c83:	10 42 0e             	adc    BYTE PTR [rdx+0xe],al
 c86:	08 00                	or     BYTE PTR [rax],al
 c88:	10 00                	adc    BYTE PTR [rax],al
 c8a:	00 00                	add    BYTE PTR [rax],al
 c8c:	cc                   	int3   
 c8d:	00 00                	add    BYTE PTR [rax],al
 c8f:	00 70 fe             	add    BYTE PTR [rax-0x2],dh
 c92:	ff                   	(bad)  
 c93:	ff 02                	inc    DWORD PTR [rdx]
 c95:	00 00                	add    BYTE PTR [rax],al
 c97:	00 00                	add    BYTE PTR [rax],al
 c99:	00 00                	add    BYTE PTR [rax],al
	...

0000000000000c9c <__FRAME_END__>:
 c9c:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .init_array:

0000000000200d70 <__frame_dummy_init_array_entry>:
  200d70:	60                   	(bad)  
  200d71:	09 00                	or     DWORD PTR [rax],eax
  200d73:	00 00                	add    BYTE PTR [rax],al
  200d75:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .fini_array:

0000000000200d78 <__do_global_dtors_aux_fini_array_entry>:
  200d78:	20 09                	and    BYTE PTR [rcx],cl
  200d7a:	00 00                	add    BYTE PTR [rax],al
  200d7c:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .dynamic:

0000000000200d80 <_DYNAMIC>:
  200d80:	01 00                	add    DWORD PTR [rax],eax
  200d82:	00 00                	add    BYTE PTR [rax],al
  200d84:	00 00                	add    BYTE PTR [rax],al
  200d86:	00 00                	add    BYTE PTR [rax],al
  200d88:	01 00                	add    DWORD PTR [rax],eax
  200d8a:	00 00                	add    BYTE PTR [rax],al
  200d8c:	00 00                	add    BYTE PTR [rax],al
  200d8e:	00 00                	add    BYTE PTR [rax],al
  200d90:	0c 00                	or     al,0x0
  200d92:	00 00                	add    BYTE PTR [rax],al
  200d94:	00 00                	add    BYTE PTR [rax],al
  200d96:	00 00                	add    BYTE PTR [rax],al
  200d98:	80 07 00             	add    BYTE PTR [rdi],0x0
  200d9b:	00 00                	add    BYTE PTR [rax],al
  200d9d:	00 00                	add    BYTE PTR [rax],al
  200d9f:	00 0d 00 00 00 00    	add    BYTE PTR [rip+0x0],cl        # 200da5 <_DYNAMIC+0x25>
  200da5:	00 00                	add    BYTE PTR [rax],al
  200da7:	00 04 0b             	add    BYTE PTR [rbx+rcx*1],al
  200daa:	00 00                	add    BYTE PTR [rax],al
  200dac:	00 00                	add    BYTE PTR [rax],al
  200dae:	00 00                	add    BYTE PTR [rax],al
  200db0:	19 00                	sbb    DWORD PTR [rax],eax
  200db2:	00 00                	add    BYTE PTR [rax],al
  200db4:	00 00                	add    BYTE PTR [rax],al
  200db6:	00 00                	add    BYTE PTR [rax],al
  200db8:	70 0d                	jo     200dc7 <_DYNAMIC+0x47>
  200dba:	20 00                	and    BYTE PTR [rax],al
  200dbc:	00 00                	add    BYTE PTR [rax],al
  200dbe:	00 00                	add    BYTE PTR [rax],al
  200dc0:	1b 00                	sbb    eax,DWORD PTR [rax]
  200dc2:	00 00                	add    BYTE PTR [rax],al
  200dc4:	00 00                	add    BYTE PTR [rax],al
  200dc6:	00 00                	add    BYTE PTR [rax],al
  200dc8:	08 00                	or     BYTE PTR [rax],al
  200dca:	00 00                	add    BYTE PTR [rax],al
  200dcc:	00 00                	add    BYTE PTR [rax],al
  200dce:	00 00                	add    BYTE PTR [rax],al
  200dd0:	1a 00                	sbb    al,BYTE PTR [rax]
  200dd2:	00 00                	add    BYTE PTR [rax],al
  200dd4:	00 00                	add    BYTE PTR [rax],al
  200dd6:	00 00                	add    BYTE PTR [rax],al
  200dd8:	78 0d                	js     200de7 <_DYNAMIC+0x67>
  200dda:	20 00                	and    BYTE PTR [rax],al
  200ddc:	00 00                	add    BYTE PTR [rax],al
  200dde:	00 00                	add    BYTE PTR [rax],al
  200de0:	1c 00                	sbb    al,0x0
  200de2:	00 00                	add    BYTE PTR [rax],al
  200de4:	00 00                	add    BYTE PTR [rax],al
  200de6:	00 00                	add    BYTE PTR [rax],al
  200de8:	08 00                	or     BYTE PTR [rax],al
  200dea:	00 00                	add    BYTE PTR [rax],al
  200dec:	00 00                	add    BYTE PTR [rax],al
  200dee:	00 00                	add    BYTE PTR [rax],al
  200df0:	f5                   	cmc    
  200df1:	fe                   	(bad)  
  200df2:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  200df5:	00 00                	add    BYTE PTR [rax],al
  200df7:	00 98 02 00 00 00    	add    BYTE PTR [rax+0x2],bl
  200dfd:	00 00                	add    BYTE PTR [rax],al
  200dff:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 200e05 <_DYNAMIC+0x85>
  200e05:	00 00                	add    BYTE PTR [rax],al
  200e07:	00 70 04             	add    BYTE PTR [rax+0x4],dh
  200e0a:	00 00                	add    BYTE PTR [rax],al
  200e0c:	00 00                	add    BYTE PTR [rax],al
  200e0e:	00 00                	add    BYTE PTR [rax],al
  200e10:	06                   	(bad)  
  200e11:	00 00                	add    BYTE PTR [rax],al
  200e13:	00 00                	add    BYTE PTR [rax],al
  200e15:	00 00                	add    BYTE PTR [rax],al
  200e17:	00 c0                	add    al,al
  200e19:	02 00                	add    al,BYTE PTR [rax]
  200e1b:	00 00                	add    BYTE PTR [rax],al
  200e1d:	00 00                	add    BYTE PTR [rax],al
  200e1f:	00 0a                	add    BYTE PTR [rdx],cl
  200e21:	00 00                	add    BYTE PTR [rax],al
  200e23:	00 00                	add    BYTE PTR [rax],al
  200e25:	00 00                	add    BYTE PTR [rax],al
  200e27:	00 d8                	add    al,bl
  200e29:	00 00                	add    BYTE PTR [rax],al
  200e2b:	00 00                	add    BYTE PTR [rax],al
  200e2d:	00 00                	add    BYTE PTR [rax],al
  200e2f:	00 0b                	add    BYTE PTR [rbx],cl
  200e31:	00 00                	add    BYTE PTR [rax],al
  200e33:	00 00                	add    BYTE PTR [rax],al
  200e35:	00 00                	add    BYTE PTR [rax],al
  200e37:	00 18                	add    BYTE PTR [rax],bl
  200e39:	00 00                	add    BYTE PTR [rax],al
  200e3b:	00 00                	add    BYTE PTR [rax],al
  200e3d:	00 00                	add    BYTE PTR [rax],al
  200e3f:	00 15 00 00 00 00    	add    BYTE PTR [rip+0x0],dl        # 200e45 <_DYNAMIC+0xc5>
	...
  200e4d:	00 00                	add    BYTE PTR [rax],al
  200e4f:	00 03                	add    BYTE PTR [rbx],al
  200e51:	00 00                	add    BYTE PTR [rax],al
  200e53:	00 00                	add    BYTE PTR [rax],al
  200e55:	00 00                	add    BYTE PTR [rax],al
  200e57:	00 70 0f             	add    BYTE PTR [rax+0xf],dh
  200e5a:	20 00                	and    BYTE PTR [rax],al
  200e5c:	00 00                	add    BYTE PTR [rax],al
  200e5e:	00 00                	add    BYTE PTR [rax],al
  200e60:	02 00                	add    al,BYTE PTR [rax]
  200e62:	00 00                	add    BYTE PTR [rax],al
  200e64:	00 00                	add    BYTE PTR [rax],al
  200e66:	00 00                	add    BYTE PTR [rax],al
  200e68:	f0 00 00             	lock add BYTE PTR [rax],al
  200e6b:	00 00                	add    BYTE PTR [rax],al
  200e6d:	00 00                	add    BYTE PTR [rax],al
  200e6f:	00 14 00             	add    BYTE PTR [rax+rax*1],dl
  200e72:	00 00                	add    BYTE PTR [rax],al
  200e74:	00 00                	add    BYTE PTR [rax],al
  200e76:	00 00                	add    BYTE PTR [rax],al
  200e78:	07                   	(bad)  
  200e79:	00 00                	add    BYTE PTR [rax],al
  200e7b:	00 00                	add    BYTE PTR [rax],al
  200e7d:	00 00                	add    BYTE PTR [rax],al
  200e7f:	00 17                	add    BYTE PTR [rdi],dl
  200e81:	00 00                	add    BYTE PTR [rax],al
  200e83:	00 00                	add    BYTE PTR [rax],al
  200e85:	00 00                	add    BYTE PTR [rax],al
  200e87:	00 90 06 00 00 00    	add    BYTE PTR [rax+0x6],dl
  200e8d:	00 00                	add    BYTE PTR [rax],al
  200e8f:	00 07                	add    BYTE PTR [rdi],al
  200e91:	00 00                	add    BYTE PTR [rax],al
  200e93:	00 00                	add    BYTE PTR [rax],al
  200e95:	00 00                	add    BYTE PTR [rax],al
  200e97:	00 a0 05 00 00 00    	add    BYTE PTR [rax+0x5],ah
  200e9d:	00 00                	add    BYTE PTR [rax],al
  200e9f:	00 08                	add    BYTE PTR [rax],cl
  200ea1:	00 00                	add    BYTE PTR [rax],al
  200ea3:	00 00                	add    BYTE PTR [rax],al
  200ea5:	00 00                	add    BYTE PTR [rax],al
  200ea7:	00 f0                	add    al,dh
  200ea9:	00 00                	add    BYTE PTR [rax],al
  200eab:	00 00                	add    BYTE PTR [rax],al
  200ead:	00 00                	add    BYTE PTR [rax],al
  200eaf:	00 09                	add    BYTE PTR [rcx],cl
  200eb1:	00 00                	add    BYTE PTR [rax],al
  200eb3:	00 00                	add    BYTE PTR [rax],al
  200eb5:	00 00                	add    BYTE PTR [rax],al
  200eb7:	00 18                	add    BYTE PTR [rax],bl
  200eb9:	00 00                	add    BYTE PTR [rax],al
  200ebb:	00 00                	add    BYTE PTR [rax],al
  200ebd:	00 00                	add    BYTE PTR [rax],al
  200ebf:	00 1e                	add    BYTE PTR [rsi],bl
  200ec1:	00 00                	add    BYTE PTR [rax],al
  200ec3:	00 00                	add    BYTE PTR [rax],al
  200ec5:	00 00                	add    BYTE PTR [rax],al
  200ec7:	00 08                	add    BYTE PTR [rax],cl
  200ec9:	00 00                	add    BYTE PTR [rax],al
  200ecb:	00 00                	add    BYTE PTR [rax],al
  200ecd:	00 00                	add    BYTE PTR [rax],al
  200ecf:	00 fb                	add    bl,bh
  200ed1:	ff                   	(bad)  
  200ed2:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  200ed5:	00 00                	add    BYTE PTR [rax],al
  200ed7:	00 01                	add    BYTE PTR [rcx],al
  200ed9:	00 00                	add    BYTE PTR [rax],al
  200edb:	08 00                	or     BYTE PTR [rax],al
  200edd:	00 00                	add    BYTE PTR [rax],al
  200edf:	00 fe                	add    dh,bh
  200ee1:	ff                   	(bad)  
  200ee2:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  200ee5:	00 00                	add    BYTE PTR [rax],al
  200ee7:	00 70 05             	add    BYTE PTR [rax+0x5],dh
  200eea:	00 00                	add    BYTE PTR [rax],al
  200eec:	00 00                	add    BYTE PTR [rax],al
  200eee:	00 00                	add    BYTE PTR [rax],al
  200ef0:	ff                   	(bad)  
  200ef1:	ff                   	(bad)  
  200ef2:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  200ef5:	00 00                	add    BYTE PTR [rax],al
  200ef7:	00 01                	add    BYTE PTR [rcx],al
  200ef9:	00 00                	add    BYTE PTR [rax],al
  200efb:	00 00                	add    BYTE PTR [rax],al
  200efd:	00 00                	add    BYTE PTR [rax],al
  200eff:	00 f0                	add    al,dh
  200f01:	ff                   	(bad)  
  200f02:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  200f05:	00 00                	add    BYTE PTR [rax],al
  200f07:	00 48 05             	add    BYTE PTR [rax+0x5],cl
  200f0a:	00 00                	add    BYTE PTR [rax],al
  200f0c:	00 00                	add    BYTE PTR [rax],al
  200f0e:	00 00                	add    BYTE PTR [rax],al
  200f10:	f9                   	stc    
  200f11:	ff                   	(bad)  
  200f12:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  200f15:	00 00                	add    BYTE PTR [rax],al
  200f17:	00 03                	add    BYTE PTR [rbx],al
	...

Disassembly of section .got:

0000000000200f70 <_GLOBAL_OFFSET_TABLE_>:
  200f70:	80 0d 20 00 00 00 00 	or     BYTE PTR [rip+0x20],0x0        # 200f97 <_GLOBAL_OFFSET_TABLE_+0x27>
	...
  200f87:	00 b6 07 00 00 00    	add    BYTE PTR [rsi+0x7],dh
  200f8d:	00 00                	add    BYTE PTR [rax],al
  200f8f:	00 c6                	add    dh,al
  200f91:	07                   	(bad)  
  200f92:	00 00                	add    BYTE PTR [rax],al
  200f94:	00 00                	add    BYTE PTR [rax],al
  200f96:	00 00                	add    BYTE PTR [rax],al
  200f98:	d6                   	(bad)  
  200f99:	07                   	(bad)  
  200f9a:	00 00                	add    BYTE PTR [rax],al
  200f9c:	00 00                	add    BYTE PTR [rax],al
  200f9e:	00 00                	add    BYTE PTR [rax],al
  200fa0:	e6 07                	out    0x7,al
  200fa2:	00 00                	add    BYTE PTR [rax],al
  200fa4:	00 00                	add    BYTE PTR [rax],al
  200fa6:	00 00                	add    BYTE PTR [rax],al
  200fa8:	f6 07 00             	test   BYTE PTR [rdi],0x0
  200fab:	00 00                	add    BYTE PTR [rax],al
  200fad:	00 00                	add    BYTE PTR [rax],al
  200faf:	00 06                	add    BYTE PTR [rsi],al
  200fb1:	08 00                	or     BYTE PTR [rax],al
  200fb3:	00 00                	add    BYTE PTR [rax],al
  200fb5:	00 00                	add    BYTE PTR [rax],al
  200fb7:	00 16                	add    BYTE PTR [rsi],dl
  200fb9:	08 00                	or     BYTE PTR [rax],al
  200fbb:	00 00                	add    BYTE PTR [rax],al
  200fbd:	00 00                	add    BYTE PTR [rax],al
  200fbf:	00 26                	add    BYTE PTR [rsi],ah
  200fc1:	08 00                	or     BYTE PTR [rax],al
  200fc3:	00 00                	add    BYTE PTR [rax],al
  200fc5:	00 00                	add    BYTE PTR [rax],al
  200fc7:	00 36                	add    BYTE PTR [rsi],dh
  200fc9:	08 00                	or     BYTE PTR [rax],al
  200fcb:	00 00                	add    BYTE PTR [rax],al
  200fcd:	00 00                	add    BYTE PTR [rax],al
  200fcf:	00 46 08             	add    BYTE PTR [rsi+0x8],al
	...

Disassembly of section .data:

0000000000201000 <__data_start>:
	...

0000000000201008 <__dso_handle>:
  201008:	08 10                	or     BYTE PTR [rax],dl
  20100a:	20 00                	and    BYTE PTR [rax],al
  20100c:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .bss:

0000000000201010 <stdout@@GLIBC_2.2.5>:
	...

0000000000201020 <stdin@@GLIBC_2.2.5>:
	...

0000000000201028 <completed.7698>:
	...

Disassembly of section .comment:

0000000000000000 <.comment>:
   0:	47                   	rex.RXB
   1:	43                   	rex.XB
   2:	43 3a 20             	rex.XB cmp spl,BYTE PTR [r8]
   5:	28 55 62             	sub    BYTE PTR [rbp+0x62],dl
   8:	75 6e                	jne    78 <_init-0x708>
   a:	74 75                	je     81 <_init-0x6ff>
   c:	20 37                	and    BYTE PTR [rdi],dh
   e:	2e 35 2e 30 2d 33    	cs xor eax,0x332d302e
  14:	75 62                	jne    78 <_init-0x708>
  16:	75 6e                	jne    86 <_init-0x6fa>
  18:	74 75                	je     8f <_init-0x6f1>
  1a:	31 7e 31             	xor    DWORD PTR [rsi+0x31],edi
  1d:	38 2e                	cmp    BYTE PTR [rsi],ch
  1f:	30 34 29             	xor    BYTE PTR [rcx+rbp*1],dh
  22:	20 37                	and    BYTE PTR [rdi],dh
  24:	2e                   	cs
  25:	35                   	.byte 0x35
  26:	2e 30 00             	xor    BYTE PTR cs:[rax],al

Disassembly of section .debug_aranges:

0000000000000000 <.debug_aranges>:
   0:	2c 00                	sub    al,0x0
   2:	00 00                	add    BYTE PTR [rax],al
   4:	02 00                	add    al,BYTE PTR [rax]
   6:	00 00                	add    BYTE PTR [rax],al
   8:	00 00                	add    BYTE PTR [rax],al
   a:	08 00                	or     BYTE PTR [rax],al
   c:	00 00                	add    BYTE PTR [rax],al
   e:	00 00                	add    BYTE PTR [rax],al
  10:	6a 09                	push   0x9
  12:	00 00                	add    BYTE PTR [rax],al
  14:	00 00                	add    BYTE PTR [rax],al
  16:	00 00                	add    BYTE PTR [rax],al
  18:	18 01                	sbb    BYTE PTR [rcx],al
	...

Disassembly of section .debug_info:

0000000000000000 <.debug_info>:
   0:	14 04                	adc    al,0x4
   2:	00 00                	add    BYTE PTR [rax],al
   4:	04 00                	add    al,0x0
   6:	00 00                	add    BYTE PTR [rax],al
   8:	00 00                	add    BYTE PTR [rax],al
   a:	08 01                	or     BYTE PTR [rcx],al
   c:	09 02                	or     DWORD PTR [rdx],eax
   e:	00 00                	add    BYTE PTR [rax],al
  10:	0c d4                	or     al,0xd4
  12:	02 00                	add    al,BYTE PTR [rax]
  14:	00 e1                	add    cl,ah
  16:	01 00                	add    DWORD PTR [rax],eax
  18:	00 6a 09             	add    BYTE PTR [rdx+0x9],ch
  1b:	00 00                	add    BYTE PTR [rax],al
  1d:	00 00                	add    BYTE PTR [rax],al
  1f:	00 00                	add    BYTE PTR [rax],al
  21:	18 01                	sbb    BYTE PTR [rcx],al
	...
  2b:	00 00                	add    BYTE PTR [rax],al
  2d:	02 37                	add    dh,BYTE PTR [rdi]
  2f:	00 00                	add    BYTE PTR [rax],al
  31:	00 02                	add    BYTE PTR [rdx],al
  33:	d8 38                	fdivr  DWORD PTR [rax]
  35:	00 00                	add    BYTE PTR [rax],al
  37:	00 03                	add    BYTE PTR [rbx],al
  39:	08 07                	or     BYTE PTR [rdi],al
  3b:	20 01                	and    BYTE PTR [rcx],al
  3d:	00 00                	add    BYTE PTR [rax],al
  3f:	03 01                	add    eax,DWORD PTR [rcx]
  41:	08 0d 01 00 00 03    	or     BYTE PTR [rip+0x3000001],cl        # 3000048 <_end+0x2dff018>
  47:	02 07                	add    al,BYTE PTR [rdi]
  49:	a7                   	cmps   DWORD PTR ds:[rsi],DWORD PTR es:[rdi]
  4a:	01 00                	add    DWORD PTR [rax],eax
  4c:	00 03                	add    BYTE PTR [rbx],al
  4e:	04 07                	add    al,0x7
  50:	25 01 00 00 03       	and    eax,0x3000001
  55:	01 06                	add    DWORD PTR [rsi],eax
  57:	0f 01 00             	sgdt   [rax]
  5a:	00 03                	add    BYTE PTR [rbx],al
  5c:	02 05 2d 00 00 00    	add    al,BYTE PTR [rip+0x2d]        # 8f <_init-0x6f1>
  62:	04 04                	add    al,0x4
  64:	05 69 6e 74 00       	add    eax,0x746e69
  69:	03 08                	add    ecx,DWORD PTR [rax]
  6b:	05 a7 00 00 00       	add    eax,0xa7
  70:	02 73 02             	add    dh,BYTE PTR [rbx+0x2]
  73:	00 00                	add    BYTE PTR [rax],al
  75:	03 8c 69 00 00 00 02 	add    ecx,DWORD PTR [rcx+rbp*2+0x2000000]
  7c:	c8 01 00 00          	enter  0x1,0x0
  80:	03 8d 69 00 00 00    	add    ecx,DWORD PTR [rbp+0x69]
  86:	05 08 06 08 8e       	add    eax,0x8e080608
  8b:	00 00                	add    BYTE PTR [rax],al
  8d:	00 03                	add    BYTE PTR [rbx],al
  8f:	01 06                	add    DWORD PTR [rsi],eax
  91:	16                   	(bad)  
  92:	01 00                	add    DWORD PTR [rax],eax
  94:	00 07                	add    BYTE PTR [rdi],al
  96:	8e 00                	mov    es,WORD PTR [rax]
  98:	00 00                	add    BYTE PTR [rax],al
  9a:	08 0e                	or     BYTE PTR [rsi],cl
  9c:	00 00                	add    BYTE PTR [rax],al
  9e:	00 d8                	add    al,bl
  a0:	04 f5                	add    al,0xf5
  a2:	1a 02                	sbb    al,BYTE PTR [rdx]
  a4:	00 00                	add    BYTE PTR [rax],al
  a6:	09 55 00             	or     DWORD PTR [rbp+0x0],edx
  a9:	00 00                	add    BYTE PTR [rax],al
  ab:	04 f6                	add    al,0xf6
  ad:	62                   	(bad)  
  ae:	00 00                	add    BYTE PTR [rax],al
  b0:	00 00                	add    BYTE PTR [rax],al
  b2:	09 c7                	or     edi,eax
  b4:	02 00                	add    al,BYTE PTR [rax]
  b6:	00 04 fb             	add    BYTE PTR [rbx+rdi*8],al
  b9:	88 00                	mov    BYTE PTR [rax],al
  bb:	00 00                	add    BYTE PTR [rax],al
  bd:	08 09                	or     BYTE PTR [rcx],cl
  bf:	7f 00                	jg     c1 <_init-0x6bf>
  c1:	00 00                	add    BYTE PTR [rax],al
  c3:	04 fc                	add    al,0xfc
  c5:	88 00                	mov    BYTE PTR [rax],al
  c7:	00 00                	add    BYTE PTR [rax],al
  c9:	10 09                	adc    BYTE PTR [rcx],cl
  cb:	89 02                	mov    DWORD PTR [rdx],eax
  cd:	00 00                	add    BYTE PTR [rax],al
  cf:	04 fd                	add    al,0xfd
  d1:	88 00                	mov    BYTE PTR [rax],al
  d3:	00 00                	add    BYTE PTR [rax],al
  d5:	18 09                	sbb    BYTE PTR [rcx],cl
  d7:	8c 00                	mov    WORD PTR [rax],es
  d9:	00 00                	add    BYTE PTR [rax],al
  db:	04 fe                	add    al,0xfe
  dd:	88 00                	mov    BYTE PTR [rax],al
  df:	00 00                	add    BYTE PTR [rax],al
  e1:	20 09                	and    BYTE PTR [rcx],cl
  e3:	47 00 00             	rex.RXB add BYTE PTR [r8],r8b
  e6:	00 04 ff             	add    BYTE PTR [rdi+rdi*8],al
  e9:	88 00                	mov    BYTE PTR [rax],al
  eb:	00 00                	add    BYTE PTR [rax],al
  ed:	28 0a                	sub    BYTE PTR [rdx],cl
  ef:	ba 01 00 00 04       	mov    edx,0x4000001
  f4:	00 01                	add    BYTE PTR [rcx],al
  f6:	88 00                	mov    BYTE PTR [rax],al
  f8:	00 00                	add    BYTE PTR [rax],al
  fa:	30 0a                	xor    BYTE PTR [rdx],cl
  fc:	66 02 00             	data16 add al,BYTE PTR [rax]
  ff:	00 04 01             	add    BYTE PTR [rcx+rax*1],al
 102:	01 88 00 00 00 38    	add    DWORD PTR [rax+0x38000000],ecx
 108:	0a 6d 01             	or     ch,BYTE PTR [rbp+0x1]
 10b:	00 00                	add    BYTE PTR [rax],al
 10d:	04 02                	add    al,0x2
 10f:	01 88 00 00 00 40    	add    DWORD PTR [rax+0x40000000],ecx
 115:	0a a6 02 00 00 04    	or     ah,BYTE PTR [rsi+0x4000002]
 11b:	04 01                	add    al,0x1
 11d:	88 00                	mov    BYTE PTR [rax],al
 11f:	00 00                	add    BYTE PTR [rax],al
 121:	48 0a 50 02          	rex.W or dl,BYTE PTR [rax+0x2]
 125:	00 00                	add    BYTE PTR [rax],al
 127:	04 05                	add    al,0x5
 129:	01 88 00 00 00 50    	add    DWORD PTR [rax+0x50000000],ecx
 12f:	0a 20                	or     ah,BYTE PTR [rax]
 131:	00 00                	add    BYTE PTR [rax],al
 133:	00 04 06             	add    BYTE PTR [rsi+rax*1],al
 136:	01 88 00 00 00 58    	add    DWORD PTR [rax+0x58000000],ecx
 13c:	0a 76 00             	or     dh,BYTE PTR [rsi+0x0]
 13f:	00 00                	add    BYTE PTR [rax],al
 141:	04 08                	add    al,0x8
 143:	01 52 02             	add    DWORD PTR [rdx+0x2],edx
 146:	00 00                	add    BYTE PTR [rax],al
 148:	60                   	(bad)  
 149:	0a da                	or     bl,dl
 14b:	01 00                	add    DWORD PTR [rax],eax
 14d:	00 04 0a             	add    BYTE PTR [rdx+rcx*1],al
 150:	01 58 02             	add    DWORD PTR [rax+0x2],ebx
 153:	00 00                	add    BYTE PTR [rax],al
 155:	68 0a d2 01 00       	push   0x1d20a
 15a:	00 04 0c             	add    BYTE PTR [rsp+rcx*1],al
 15d:	01 62 00             	add    DWORD PTR [rdx+0x0],esp
 160:	00 00                	add    BYTE PTR [rax],al
 162:	70 0a                	jo     16e <_init-0x612>
 164:	7b 02                	jnp    168 <_init-0x618>
 166:	00 00                	add    BYTE PTR [rax],al
 168:	04 10                	add    al,0x10
 16a:	01 62 00             	add    DWORD PTR [rdx+0x0],esp
 16d:	00 00                	add    BYTE PTR [rax],al
 16f:	74 0a                	je     17b <_init-0x605>
 171:	01 01                	add    DWORD PTR [rcx],eax
 173:	00 00                	add    BYTE PTR [rax],al
 175:	04 12                	add    al,0x12
 177:	01 70 00             	add    DWORD PTR [rax+0x0],esi
 17a:	00 00                	add    BYTE PTR [rax],al
 17c:	78 0a                	js     188 <_init-0x5f8>
 17e:	cc                   	int3   
 17f:	00 00                	add    BYTE PTR [rax],al
 181:	00 04 16             	add    BYTE PTR [rsi+rdx*1],al
 184:	01 46 00             	add    DWORD PTR [rsi+0x0],eax
 187:	00 00                	add    BYTE PTR [rax],al
 189:	80 0a 97             	or     BYTE PTR [rdx],0x97
 18c:	02 00                	add    al,BYTE PTR [rax]
 18e:	00 04 17             	add    BYTE PTR [rdi+rdx*1],al
 191:	01 54 00 00          	add    DWORD PTR [rax+rax*1+0x0],edx
 195:	00 82 0a 4c 01 00    	add    BYTE PTR [rdx+0x14c0a],al
 19b:	00 04 18             	add    BYTE PTR [rax+rbx*1],al
 19e:	01 5e 02             	add    DWORD PTR [rsi+0x2],ebx
 1a1:	00 00                	add    BYTE PTR [rax],al
 1a3:	83 0a bb             	or     DWORD PTR [rdx],0xffffffbb
 1a6:	00 00                	add    BYTE PTR [rax],al
 1a8:	00 04 1c             	add    BYTE PTR [rsp+rbx*1],al
 1ab:	01 6e 02             	add    DWORD PTR [rsi+0x2],ebp
 1ae:	00 00                	add    BYTE PTR [rax],al
 1b0:	88 0a                	mov    BYTE PTR [rdx],cl
 1b2:	05 01 00 00 04       	add    eax,0x4000001
 1b7:	25 01 7b 00 00       	and    eax,0x7b01
 1bc:	00 90 0a 56 01 00    	add    BYTE PTR [rax+0x1560a],dl
 1c2:	00 04 2d 01 86 00 00 	add    BYTE PTR [rbp*1+0x8601],al
 1c9:	00 98 0a 8b 01 00    	add    BYTE PTR [rax+0x18b0a],bl
 1cf:	00 04 2e             	add    BYTE PTR [rsi+rbp*1],al
 1d2:	01 86 00 00 00 a0    	add    DWORD PTR [rsi-0x60000000],eax
 1d8:	0a 92 01 00 00 04    	or     dl,BYTE PTR [rdx+0x4000001]
 1de:	2f                   	(bad)  
 1df:	01 86 00 00 00 a8    	add    DWORD PTR [rsi-0x58000000],eax
 1e5:	0a 99 01 00 00 04    	or     bl,BYTE PTR [rcx+0x4000001]
 1eb:	30 01                	xor    BYTE PTR [rcx],al
 1ed:	86 00                	xchg   BYTE PTR [rax],al
 1ef:	00 00                	add    BYTE PTR [rax],al
 1f1:	b0 0a                	mov    al,0xa
 1f3:	a0 01 00 00 04 32 01 	movabs al,ds:0x2d013204000001
 1fa:	2d 00 
 1fc:	00 00                	add    BYTE PTR [rax],al
 1fe:	b8 0a 83 02 00       	mov    eax,0x2830a
 203:	00 04 33             	add    BYTE PTR [rbx+rsi*1],al
 206:	01 62 00             	add    DWORD PTR [rdx+0x0],esp
 209:	00 00                	add    BYTE PTR [rax],al
 20b:	c0 0a 5d             	ror    BYTE PTR [rdx],0x5d
 20e:	01 00                	add    DWORD PTR [rax],eax
 210:	00 04 35 01 74 02 00 	add    BYTE PTR [rsi*1+0x27401],al
 217:	00 c4                	add    ah,al
 219:	00 0b                	add    BYTE PTR [rbx],cl
 21b:	e3 02                	jrcxz  21f <_init-0x561>
 21d:	00 00                	add    BYTE PTR [rax],al
 21f:	04 9a                	add    al,0x9a
 221:	08 41 01             	or     BYTE PTR [rcx+0x1],al
 224:	00 00                	add    BYTE PTR [rax],al
 226:	18 04 a0             	sbb    BYTE PTR [rax+riz*4],al
 229:	52                   	push   rdx
 22a:	02 00                	add    al,BYTE PTR [rax]
 22c:	00 09                	add    BYTE PTR [rcx],cl
 22e:	7e 01                	jle    231 <_init-0x54f>
 230:	00 00                	add    BYTE PTR [rax],al
 232:	04 a1                	add    al,0xa1
 234:	52                   	push   rdx
 235:	02 00                	add    al,BYTE PTR [rax]
 237:	00 00                	add    BYTE PTR [rax],al
 239:	09 fb                	or     ebx,edi
 23b:	00 00                	add    BYTE PTR [rax],al
 23d:	00 04 a2             	add    BYTE PTR [rdx+riz*4],al
 240:	58                   	pop    rax
 241:	02 00                	add    al,BYTE PTR [rax]
 243:	00 08                	add    BYTE PTR [rax],cl
 245:	09 f6                	or     esi,esi
 247:	00 00                	add    BYTE PTR [rax],al
 249:	00 04 a6             	add    BYTE PTR [rsi+riz*4],al
 24c:	62                   	(bad)  
 24d:	00 00                	add    BYTE PTR [rax],al
 24f:	00 10                	add    BYTE PTR [rax],dl
 251:	00 06                	add    BYTE PTR [rsi],al
 253:	08 21                	or     BYTE PTR [rcx],ah
 255:	02 00                	add    al,BYTE PTR [rax]
 257:	00 06                	add    BYTE PTR [rsi],al
 259:	08 9a 00 00 00 0c    	or     BYTE PTR [rdx+0xc000000],bl
 25f:	8e 00                	mov    es,WORD PTR [rax]
 261:	00 00                	add    BYTE PTR [rax],al
 263:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 264:	02 00                	add    al,BYTE PTR [rax]
 266:	00 0d 38 00 00 00    	add    BYTE PTR [rip+0x38],cl        # 2a4 <_init-0x4dc>
 26c:	00 00                	add    BYTE PTR [rax],al
 26e:	06                   	(bad)  
 26f:	08 1a                	or     BYTE PTR [rdx],bl
 271:	02 00                	add    al,BYTE PTR [rax]
 273:	00 0c 8e             	add    BYTE PTR [rsi+rcx*4],cl
 276:	00 00                	add    BYTE PTR [rax],al
 278:	00 84 02 00 00 0d 38 	add    BYTE PTR [rdx+rax*1+0x380d0000],al
 27f:	00 00                	add    BYTE PTR [rax],al
 281:	00 13                	add    BYTE PTR [rbx],dl
 283:	00 0e                	add    BYTE PTR [rsi],cl
 285:	e8 00 00 00 0f       	call   f00028a <_end+0xedff25a>
 28a:	32 01                	xor    al,BYTE PTR [rcx]
 28c:	00 00                	add    BYTE PTR [rax],al
 28e:	04 3f                	add    al,0x3f
 290:	01 84 02 00 00 0f 5c 	add    DWORD PTR [rdx+rax*1+0x5c0f0000],eax
 297:	00 00                	add    BYTE PTR [rax],al
 299:	00 04 40             	add    BYTE PTR [rax+rax*2],al
 29c:	01 84 02 00 00 0f d8 	add    DWORD PTR [rdx+rax*1-0x27f10000],eax
 2a3:	00 00                	add    BYTE PTR [rax],al
 2a5:	00 04 41             	add    BYTE PTR [rcx+rax*2],al
 2a8:	01 84 02 00 00 06 08 	add    DWORD PTR [rdx+rax*1+0x8060000],eax
 2af:	95                   	xchg   ebp,eax
 2b0:	00 00                	add    BYTE PTR [rax],al
 2b2:	00 07                	add    BYTE PTR [rdi],al
 2b4:	ad                   	lods   eax,DWORD PTR ds:[rsi]
 2b5:	02 00                	add    al,BYTE PTR [rax]
 2b7:	00 10                	add    BYTE PTR [rax],dl
 2b9:	60                   	(bad)  
 2ba:	02 00                	add    al,BYTE PTR [rax]
 2bc:	00 05 87 58 02 00    	add    BYTE PTR [rip+0x25887],al        # 25b49 <__FRAME_END__+0x24ead>
 2c2:	00 10                	add    BYTE PTR [rax],dl
 2c4:	dc 02                	fadd   QWORD PTR [rdx]
 2c6:	00 00                	add    BYTE PTR [rax],al
 2c8:	05 88 58 02 00       	add    eax,0x25888
 2cd:	00 10                	add    BYTE PTR [rax],dl
 2cf:	9b                   	fwait
 2d0:	00 00                	add    BYTE PTR [rax],al
 2d2:	00 05 89 58 02 00    	add    BYTE PTR [rip+0x25889],al        # 25b61 <__FRAME_END__+0x24ec5>
 2d8:	00 10                	add    BYTE PTR [rax],dl
 2da:	17                   	(bad)  
 2db:	00 00                	add    BYTE PTR [rax],al
 2dd:	00 06                	add    BYTE PTR [rsi],al
 2df:	1a 62 00             	sbb    ah,BYTE PTR [rdx+0x0]
 2e2:	00 00                	add    BYTE PTR [rax],al
 2e4:	0c b3                	or     al,0xb3
 2e6:	02 00                	add    al,BYTE PTR [rax]
 2e8:	00 ef                	add    bh,ch
 2ea:	02 00                	add    al,BYTE PTR [rax]
 2ec:	00 11                	add    BYTE PTR [rcx],dl
 2ee:	00 07                	add    BYTE PTR [rdi],al
 2f0:	e4 02                	in     al,0x2
 2f2:	00 00                	add    BYTE PTR [rax],al
 2f4:	10 b4 02 00 00 06 1b 	adc    BYTE PTR [rdx+rax*1+0x1b060000],dh
 2fb:	ef                   	out    dx,eax
 2fc:	02 00                	add    al,BYTE PTR [rax]
 2fe:	00 03                	add    BYTE PTR [rbx],al
 300:	08 05 a2 00 00 00    	or     BYTE PTR [rip+0xa2],al        # 3a8 <_init-0x3d8>
 306:	03 08                	add    ecx,DWORD PTR [rax]
 308:	07                   	(bad)  
 309:	1b 01                	sbb    eax,DWORD PTR [rcx]
 30b:	00 00                	add    BYTE PTR [rax],al
 30d:	0c 88                	or     al,0x88
 30f:	00 00                	add    BYTE PTR [rax],al
 311:	00 1d 03 00 00 0d    	add    BYTE PTR [rip+0xd000003],bl        # d00031a <_end+0xcdff2ea>
 317:	38 00                	cmp    BYTE PTR [rax],al
 319:	00 00                	add    BYTE PTR [rax],al
 31b:	01 00                	add    DWORD PTR [rax],eax
 31d:	10 3e                	adc    BYTE PTR [rsi],bh
 31f:	00 00                	add    BYTE PTR [rax],al
 321:	00 07                	add    BYTE PTR [rdi],al
 323:	9f                   	lahf   
 324:	0d 03 00 00 10       	or     eax,0x10000003
 329:	c1 00 00             	rol    DWORD PTR [rax],0x0
 32c:	00 07                	add    BYTE PTR [rdi],al
 32e:	a0 62 00 00 00 10 b0 	movabs al,ds:0xb01000000062
 335:	00 00 
 337:	00 07                	add    BYTE PTR [rdi],al
 339:	a1 69 00 00 00 10 40 	movabs eax,ds:0x401000000069
 340:	00 00 
 342:	00 07                	add    BYTE PTR [rdi],al
 344:	a6                   	cmps   BYTE PTR ds:[rsi],BYTE PTR es:[rdi]
 345:	0d 03 00 00 10       	or     eax,0x10000003
 34a:	c3                   	ret    
 34b:	00 00                	add    BYTE PTR [rax],al
 34d:	00 07                	add    BYTE PTR [rdi],al
 34f:	ae                   	scas   al,BYTE PTR es:[rdi]
 350:	62                   	(bad)  
 351:	00 00                	add    BYTE PTR [rax],al
 353:	00 10                	add    BYTE PTR [rax],dl
 355:	b2 00                	mov    dl,0x0
 357:	00 00                	add    BYTE PTR [rax],al
 359:	07                   	(bad)  
 35a:	af                   	scas   eax,DWORD PTR es:[rdi]
 35b:	69 00 00 00 0f 6c    	imul   eax,DWORD PTR [rax],0x6c0f0000
 361:	00 00                	add    BYTE PTR [rax],al
 363:	00 08                	add    BYTE PTR [rax],cl
 365:	22 02                	and    al,BYTE PTR [rdx]
 367:	6b 03 00             	imul   eax,DWORD PTR [rbx],0x0
 36a:	00 06                	add    BYTE PTR [rsi],al
 36c:	08 88 00 00 00 10    	or     BYTE PTR [rax+0x10000000],cl
 372:	07                   	(bad)  
 373:	00 00                	add    BYTE PTR [rax],al
 375:	00 09                	add    BYTE PTR [rcx],cl
 377:	24 88                	and    al,0x88
 379:	00 00                	add    BYTE PTR [rax],al
 37b:	00 10                	add    BYTE PTR [rax],dl
 37d:	00 00                	add    BYTE PTR [rax],al
 37f:	00 00                	add    BYTE PTR [rax],al
 381:	09 32                	or     DWORD PTR [rdx],esi
 383:	62                   	(bad)  
 384:	00 00                	add    BYTE PTR [rax],al
 386:	00 10                	add    BYTE PTR [rax],dl
 388:	66 01 00             	add    WORD PTR [rax],ax
 38b:	00 09                	add    BYTE PTR [rcx],cl
 38d:	37                   	(bad)  
 38e:	62                   	(bad)  
 38f:	00 00                	add    BYTE PTR [rax],al
 391:	00 10                	add    BYTE PTR [rax],dl
 393:	c0 02 00             	rol    BYTE PTR [rdx],0x0
 396:	00 09                	add    BYTE PTR [rcx],cl
 398:	3b 62 00             	cmp    esp,DWORD PTR [rdx+0x0]
 39b:	00 00                	add    BYTE PTR [rax],al
 39d:	12 79 01             	adc    bh,BYTE PTR [rcx+0x1]
 3a0:	00 00                	add    BYTE PTR [rax],al
 3a2:	01 07                	add    DWORD PTR [rdi],eax
 3a4:	62                   	(bad)  
 3a5:	00 00                	add    BYTE PTR [rax],al
 3a7:	00 6a 09             	add    BYTE PTR [rdx+0x9],ch
 3aa:	00 00                	add    BYTE PTR [rax],al
 3ac:	00 00                	add    BYTE PTR [rax],al
 3ae:	00 00                	add    BYTE PTR [rax],al
 3b0:	18 01                	sbb    BYTE PTR [rcx],al
 3b2:	00 00                	add    BYTE PTR [rax],al
 3b4:	00 00                	add    BYTE PTR [rax],al
 3b6:	00 00                	add    BYTE PTR [rax],al
 3b8:	01 9c 0b 04 00 00 13 	add    DWORD PTR [rbx+rcx*1+0x13000004],ebx
 3bf:	14 01                	adc    al,0x1
 3c1:	08 df                	or     bh,bl
 3c3:	03 00                	add    eax,DWORD PTR [rax]
 3c5:	00 14 62             	add    BYTE PTR [rdx+riz*2],dl
 3c8:	75 66                	jne    430 <_init-0x350>
 3ca:	00 01                	add    BYTE PTR [rcx],al
 3cc:	09 0b                	or     DWORD PTR [rbx],ecx
 3ce:	04 00                	add    al,0x0
 3d0:	00 00                	add    BYTE PTR [rax],al
 3d2:	09 84 01 00 00 01 0a 	or     DWORD PTR [rcx+rax*1+0xa010000],eax
 3d9:	62                   	(bad)  
 3da:	00 00                	add    BYTE PTR [rax],al
 3dc:	00 10                	add    BYTE PTR [rax],dl
 3de:	00 15 64 00 01 0b    	add    BYTE PTR [rip+0xb010064],dl        # b010448 <_end+0xae0f418>
 3e4:	be 03 00 00 02       	mov    esi,0x2000003
 3e9:	91                   	xchg   ecx,eax
 3ea:	40 16                	rex (bad) 
 3ec:	11 0a                	adc    DWORD PTR [rdx],ecx
 3ee:	00 00                	add    BYTE PTR [rax],al
 3f0:	00 00                	add    BYTE PTR [rax],al
 3f2:	00 00                	add    BYTE PTR [rax],al
 3f4:	51                   	push   rcx
 3f5:	00 00                	add    BYTE PTR [rax],al
 3f7:	00 00                	add    BYTE PTR [rax],al
 3f9:	00 00                	add    BYTE PTR [rax],al
 3fb:	00 15 67 00 01 14    	add    BYTE PTR [rip+0x14010067],dl        # 14010468 <_end+0x13e0f438>
 401:	62                   	(bad)  
 402:	00 00                	add    BYTE PTR [rax],al
 404:	00 03                	add    BYTE PTR [rbx],al
 406:	91                   	xchg   ecx,eax
 407:	bc 7f 00 00 17       	mov    esp,0x1700007f
 40c:	8e 00                	mov    es,WORD PTR [rax]
 40e:	00 00                	add    BYTE PTR [rax],al
 410:	0d 38 00 00 00       	or     eax,0x38
 415:	0f 00 00             	sldt   WORD PTR [rax]

Disassembly of section .debug_abbrev:

0000000000000000 <.debug_abbrev>:
   0:	01 11                	add    DWORD PTR [rcx],edx
   2:	01 25 0e 13 0b 03    	add    DWORD PTR [rip+0x30b130e],esp        # 30b1316 <_end+0x2eb02e6>
   8:	0e                   	(bad)  
   9:	1b 0e                	sbb    ecx,DWORD PTR [rsi]
   b:	11 01                	adc    DWORD PTR [rcx],eax
   d:	12 07                	adc    al,BYTE PTR [rdi]
   f:	10 17                	adc    BYTE PTR [rdi],dl
  11:	00 00                	add    BYTE PTR [rax],al
  13:	02 16                	add    dl,BYTE PTR [rsi]
  15:	00 03                	add    BYTE PTR [rbx],al
  17:	0e                   	(bad)  
  18:	3a 0b                	cmp    cl,BYTE PTR [rbx]
  1a:	3b 0b                	cmp    ecx,DWORD PTR [rbx]
  1c:	49 13 00             	adc    rax,QWORD PTR [r8]
  1f:	00 03                	add    BYTE PTR [rbx],al
  21:	24 00                	and    al,0x0
  23:	0b 0b                	or     ecx,DWORD PTR [rbx]
  25:	3e 0b 03             	or     eax,DWORD PTR ds:[rbx]
  28:	0e                   	(bad)  
  29:	00 00                	add    BYTE PTR [rax],al
  2b:	04 24                	add    al,0x24
  2d:	00 0b                	add    BYTE PTR [rbx],cl
  2f:	0b 3e                	or     edi,DWORD PTR [rsi]
  31:	0b 03                	or     eax,DWORD PTR [rbx]
  33:	08 00                	or     BYTE PTR [rax],al
  35:	00 05 0f 00 0b 0b    	add    BYTE PTR [rip+0xb0b000f],al        # b0b004a <_end+0xaeaf01a>
  3b:	00 00                	add    BYTE PTR [rax],al
  3d:	06                   	(bad)  
  3e:	0f 00 0b             	str    WORD PTR [rbx]
  41:	0b 49 13             	or     ecx,DWORD PTR [rcx+0x13]
  44:	00 00                	add    BYTE PTR [rax],al
  46:	07                   	(bad)  
  47:	26 00 49 13          	add    BYTE PTR es:[rcx+0x13],cl
  4b:	00 00                	add    BYTE PTR [rax],al
  4d:	08 13                	or     BYTE PTR [rbx],dl
  4f:	01 03                	add    DWORD PTR [rbx],eax
  51:	0e                   	(bad)  
  52:	0b 0b                	or     ecx,DWORD PTR [rbx]
  54:	3a 0b                	cmp    cl,BYTE PTR [rbx]
  56:	3b 0b                	cmp    ecx,DWORD PTR [rbx]
  58:	01 13                	add    DWORD PTR [rbx],edx
  5a:	00 00                	add    BYTE PTR [rax],al
  5c:	09 0d 00 03 0e 3a    	or     DWORD PTR [rip+0x3a0e0300],ecx        # 3a0e0362 <_end+0x39edf332>
  62:	0b 3b                	or     edi,DWORD PTR [rbx]
  64:	0b 49 13             	or     ecx,DWORD PTR [rcx+0x13]
  67:	38 0b                	cmp    BYTE PTR [rbx],cl
  69:	00 00                	add    BYTE PTR [rax],al
  6b:	0a 0d 00 03 0e 3a    	or     cl,BYTE PTR [rip+0x3a0e0300]        # 3a0e0371 <_end+0x39edf341>
  71:	0b 3b                	or     edi,DWORD PTR [rbx]
  73:	05 49 13 38 0b       	add    eax,0xb381349
  78:	00 00                	add    BYTE PTR [rax],al
  7a:	0b 16                	or     edx,DWORD PTR [rsi]
  7c:	00 03                	add    BYTE PTR [rbx],al
  7e:	0e                   	(bad)  
  7f:	3a 0b                	cmp    cl,BYTE PTR [rbx]
  81:	3b 0b                	cmp    ecx,DWORD PTR [rbx]
  83:	00 00                	add    BYTE PTR [rax],al
  85:	0c 01                	or     al,0x1
  87:	01 49 13             	add    DWORD PTR [rcx+0x13],ecx
  8a:	01 13                	add    DWORD PTR [rbx],edx
  8c:	00 00                	add    BYTE PTR [rax],al
  8e:	0d 21 00 49 13       	or     eax,0x13490021
  93:	2f                   	(bad)  
  94:	0b 00                	or     eax,DWORD PTR [rax]
  96:	00 0e                	add    BYTE PTR [rsi],cl
  98:	13 00                	adc    eax,DWORD PTR [rax]
  9a:	03 0e                	add    ecx,DWORD PTR [rsi]
  9c:	3c 19                	cmp    al,0x19
  9e:	00 00                	add    BYTE PTR [rax],al
  a0:	0f 34                	sysenter 
  a2:	00 03                	add    BYTE PTR [rbx],al
  a4:	0e                   	(bad)  
  a5:	3a 0b                	cmp    cl,BYTE PTR [rbx]
  a7:	3b 05 49 13 3f 19    	cmp    eax,DWORD PTR [rip+0x193f1349]        # 193f13f6 <_end+0x191f03c6>
  ad:	3c 19                	cmp    al,0x19
  af:	00 00                	add    BYTE PTR [rax],al
  b1:	10 34 00             	adc    BYTE PTR [rax+rax*1],dh
  b4:	03 0e                	add    ecx,DWORD PTR [rsi]
  b6:	3a 0b                	cmp    cl,BYTE PTR [rbx]
  b8:	3b 0b                	cmp    ecx,DWORD PTR [rbx]
  ba:	49 13 3f             	adc    rdi,QWORD PTR [r15]
  bd:	19 3c 19             	sbb    DWORD PTR [rcx+rbx*1],edi
  c0:	00 00                	add    BYTE PTR [rax],al
  c2:	11 21                	adc    DWORD PTR [rcx],esp
  c4:	00 00                	add    BYTE PTR [rax],al
  c6:	00 12                	add    BYTE PTR [rdx],dl
  c8:	2e 01 3f             	add    DWORD PTR cs:[rdi],edi
  cb:	19 03                	sbb    DWORD PTR [rbx],eax
  cd:	0e                   	(bad)  
  ce:	3a 0b                	cmp    cl,BYTE PTR [rbx]
  d0:	3b 0b                	cmp    ecx,DWORD PTR [rbx]
  d2:	49 13 11             	adc    rdx,QWORD PTR [r9]
  d5:	01 12                	add    DWORD PTR [rdx],edx
  d7:	07                   	(bad)  
  d8:	40 18 96 42 19 01 13 	sbb    BYTE PTR [rsi+0x13011942],dl
  df:	00 00                	add    BYTE PTR [rax],al
  e1:	13 13                	adc    edx,DWORD PTR [rbx]
  e3:	01 0b                	add    DWORD PTR [rbx],ecx
  e5:	0b 3a                	or     edi,DWORD PTR [rdx]
  e7:	0b 3b                	or     edi,DWORD PTR [rbx]
  e9:	0b 01                	or     eax,DWORD PTR [rcx]
  eb:	13 00                	adc    eax,DWORD PTR [rax]
  ed:	00 14 0d 00 03 08 3a 	add    BYTE PTR [rcx*1+0x3a080300],dl
  f4:	0b 3b                	or     edi,DWORD PTR [rbx]
  f6:	0b 49 13             	or     ecx,DWORD PTR [rcx+0x13]
  f9:	38 0b                	cmp    BYTE PTR [rbx],cl
  fb:	00 00                	add    BYTE PTR [rax],al
  fd:	15 34 00 03 08       	adc    eax,0x8030034
 102:	3a 0b                	cmp    cl,BYTE PTR [rbx]
 104:	3b 0b                	cmp    ecx,DWORD PTR [rbx]
 106:	49 13 02             	adc    rax,QWORD PTR [r10]
 109:	18 00                	sbb    BYTE PTR [rax],al
 10b:	00 16                	add    BYTE PTR [rsi],dl
 10d:	0b 01                	or     eax,DWORD PTR [rcx]
 10f:	11 01                	adc    DWORD PTR [rcx],eax
 111:	12 07                	adc    al,BYTE PTR [rdi]
 113:	00 00                	add    BYTE PTR [rax],al
 115:	17                   	(bad)  
 116:	01 01                	add    DWORD PTR [rcx],eax
 118:	49 13 00             	adc    rax,QWORD PTR [r8]
	...

Disassembly of section .debug_line:

0000000000000000 <.debug_line>:
   0:	07                   	(bad)  
   1:	01 00                	add    DWORD PTR [rax],eax
   3:	00 02                	add    BYTE PTR [rdx],al
   5:	00 db                	add    bl,bl
   7:	00 00                	add    BYTE PTR [rax],al
   9:	00 01                	add    BYTE PTR [rcx],al
   b:	01 fb                	add    ebx,edi
   d:	0e                   	(bad)  
   e:	0d 00 01 01 01       	or     eax,0x1010100
  13:	01 00                	add    DWORD PTR [rax],eax
  15:	00 00                	add    BYTE PTR [rax],al
  17:	01 00                	add    DWORD PTR [rax],eax
  19:	00 01                	add    BYTE PTR [rcx],al
  1b:	2f                   	(bad)  
  1c:	75 73                	jne    91 <_init-0x6ef>
  1e:	72 2f                	jb     4f <_init-0x731>
  20:	6c                   	ins    BYTE PTR es:[rdi],dx
  21:	69 62 2f 67 63 63 2f 	imul   esp,DWORD PTR [rdx+0x2f],0x2f636367
  28:	78 38                	js     62 <_init-0x71e>
  2a:	36 5f                	ss pop rdi
  2c:	36 34 2d             	ss xor al,0x2d
  2f:	6c                   	ins    BYTE PTR es:[rdi],dx
  30:	69 6e 75 78 2d 67 6e 	imul   ebp,DWORD PTR [rsi+0x75],0x6e672d78
  37:	75 2f                	jne    68 <_init-0x718>
  39:	37                   	(bad)  
  3a:	2f                   	(bad)  
  3b:	69 6e 63 6c 75 64 65 	imul   ebp,DWORD PTR [rsi+0x63],0x6564756c
  42:	00 2f                	add    BYTE PTR [rdi],ch
  44:	75 73                	jne    b9 <_init-0x6c7>
  46:	72 2f                	jb     77 <_init-0x709>
  48:	69 6e 63 6c 75 64 65 	imul   ebp,DWORD PTR [rsi+0x63],0x6564756c
  4f:	2f                   	(bad)  
  50:	78 38                	js     8a <_init-0x6f6>
  52:	36 5f                	ss pop rdi
  54:	36 34 2d             	ss xor al,0x2d
  57:	6c                   	ins    BYTE PTR es:[rdi],dx
  58:	69 6e 75 78 2d 67 6e 	imul   ebp,DWORD PTR [rsi+0x75],0x6e672d78
  5f:	75 2f                	jne    90 <_init-0x6f0>
  61:	62                   	(bad)  
  62:	69 74 73 00 2f 75 73 	imul   esi,DWORD PTR [rbx+rsi*2+0x0],0x7273752f
  69:	72 
  6a:	2f                   	(bad)  
  6b:	69 6e 63 6c 75 64 65 	imul   ebp,DWORD PTR [rsi+0x63],0x6564756c
  72:	00 00                	add    BYTE PTR [rax],al
  74:	67 75 65             	addr32 jne dc <_init-0x6a4>
  77:	73 73                	jae    ec <_init-0x694>
  79:	2e 63 00             	movsxd eax,DWORD PTR cs:[rax]
  7c:	00 00                	add    BYTE PTR [rax],al
  7e:	00 73 74             	add    BYTE PTR [rbx+0x74],dh
  81:	64 64 65 66 2e 68 00 	fs fs gs cs pushw 0x100
  88:	01 
  89:	00 00                	add    BYTE PTR [rax],al
  8b:	74 79                	je     106 <_init-0x67a>
  8d:	70 65                	jo     f4 <_init-0x68c>
  8f:	73 2e                	jae    bf <_init-0x6c1>
  91:	68 00 02 00 00       	push   0x200
  96:	6c                   	ins    BYTE PTR es:[rdi],dx
  97:	69 62 69 6f 2e 68 00 	imul   esp,DWORD PTR [rdx+0x69],0x682e6f
  9e:	02 00                	add    al,BYTE PTR [rax]
  a0:	00 73 74             	add    BYTE PTR [rbx+0x74],dh
  a3:	64 69 6f 2e 68 00 03 	imul   ebp,DWORD PTR fs:[rdi+0x2e],0x30068
  aa:	00 
  ab:	00 73 79             	add    BYTE PTR [rbx+0x79],dh
  ae:	73 5f                	jae    10f <_init-0x671>
  b0:	65 72 72             	gs jb  125 <_init-0x65b>
  b3:	6c                   	ins    BYTE PTR es:[rdi],dx
  b4:	69 73 74 2e 68 00 02 	imul   esi,DWORD PTR [rbx+0x74],0x200682e
  bb:	00 00                	add    BYTE PTR [rax],al
  bd:	74 69                	je     128 <_init-0x658>
  bf:	6d                   	ins    DWORD PTR es:[rdi],dx
  c0:	65 2e 68 00 03 00 00 	gs cs push 0x300
  c7:	75 6e                	jne    137 <_init-0x649>
  c9:	69 73 74 64 2e 68 00 	imul   esi,DWORD PTR [rbx+0x74],0x682e64
  d0:	03 00                	add    eax,DWORD PTR [rax]
  d2:	00 67 65             	add    BYTE PTR [rdi+0x65],ah
  d5:	74 6f                	je     146 <_init-0x63a>
  d7:	70 74                	jo     14d <_init-0x633>
  d9:	5f                   	pop    rdi
  da:	63 6f 72             	movsxd ebp,DWORD PTR [rdi+0x72]
  dd:	65 2e 68 00 02 00 00 	gs cs push 0x200
  e4:	00 00                	add    BYTE PTR [rax],al
  e6:	09 02                	or     DWORD PTR [rdx],eax
  e8:	6a 09                	push   0x9
  ea:	00 00                	add    BYTE PTR [rax],al
  ec:	00 00                	add    BYTE PTR [rax],al
  ee:	00 00                	add    BYTE PTR [rax],al
  f0:	18 90 ea 08 c9 08    	sbb    BYTE PTR [rax+0x8c908ea],dl
  f6:	92                   	xchg   edx,eax
  f7:	02 29                	add    ch,BYTE PTR [rcx]
  f9:	14 08                	adc    al,0x8
  fb:	13 08                	adc    ecx,DWORD PTR [rax]
  fd:	bb 08 83 08 59       	mov    ebx,0x59088308
 102:	83 d8 be             	sbb    eax,0xffffffbe
 105:	59                   	pop    rcx
 106:	02 1b                	add    bl,BYTE PTR [rbx]
 108:	00 01                	add    BYTE PTR [rcx],al
 10a:	01                   	.byte 0x1

Disassembly of section .debug_str:

0000000000000000 <.debug_str>:
   0:	6f                   	outs   dx,DWORD PTR ds:[rsi]
   1:	70 74                	jo     77 <_init-0x709>
   3:	69 6e 64 00 6f 70 74 	imul   ebp,DWORD PTR [rsi+0x64],0x74706f00
   a:	61                   	(bad)  
   b:	72 67                	jb     74 <_init-0x70c>
   d:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
  10:	4f 5f                	rex.WRXB pop r15
  12:	46                   	rex.RX
  13:	49                   	rex.WB
  14:	4c                   	rex.WR
  15:	45 00 73 79          	add    BYTE PTR [r11+0x79],r14b
  19:	73 5f                	jae    7a <_init-0x706>
  1b:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  1c:	65 72 72             	gs jb  91 <_init-0x6ef>
  1f:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
  22:	4f 5f                	rex.WRXB pop r15
  24:	73 61                	jae    87 <_init-0x6f9>
  26:	76 65                	jbe    8d <_init-0x6f3>
  28:	5f                   	pop    rdi
  29:	65 6e                	outs   dx,BYTE PTR gs:[rsi]
  2b:	64 00 73 68          	add    BYTE PTR fs:[rbx+0x68],dh
  2f:	6f                   	outs   dx,DWORD PTR ds:[rsi]
  30:	72 74                	jb     a6 <_init-0x6da>
  32:	20 69 6e             	and    BYTE PTR [rcx+0x6e],ch
  35:	74 00                	je     37 <_init-0x749>
  37:	73 69                	jae    a2 <_init-0x6de>
  39:	7a 65                	jp     a0 <_init-0x6e0>
  3b:	5f                   	pop    rdi
  3c:	74 00                	je     3e <_init-0x742>
  3e:	5f                   	pop    rdi
  3f:	5f                   	pop    rdi
  40:	74 7a                	je     bc <_init-0x6c4>
  42:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  43:	61                   	(bad)  
  44:	6d                   	ins    DWORD PTR es:[rdi],dx
  45:	65 00 5f 49          	add    BYTE PTR gs:[rdi+0x49],bl
  49:	4f 5f                	rex.WRXB pop r15
  4b:	77 72                	ja     bf <_init-0x6c1>
  4d:	69 74 65 5f 70 74 72 	imul   esi,DWORD PTR [rbp+riz*2+0x5f],0x727470
  54:	00 
  55:	5f                   	pop    rdi
  56:	66 6c                	data16 ins BYTE PTR es:[rdi],dx
  58:	61                   	(bad)  
  59:	67 73 00             	addr32 jae 5c <_init-0x724>
  5c:	5f                   	pop    rdi
  5d:	49                   	rex.WB
  5e:	4f 5f                	rex.WRXB pop r15
  60:	32 5f 31             	xor    bl,BYTE PTR [rdi+0x31]
  63:	5f                   	pop    rdi
  64:	73 74                	jae    da <_init-0x6a6>
  66:	64 6f                	outs   dx,DWORD PTR fs:[rsi]
  68:	75 74                	jne    de <_init-0x6a2>
  6a:	5f                   	pop    rdi
  6b:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
  6e:	65 6e                	outs   dx,BYTE PTR gs:[rsi]
  70:	76 69                	jbe    db <_init-0x6a5>
  72:	72 6f                	jb     e3 <_init-0x69d>
  74:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  75:	00 5f 6d             	add    BYTE PTR [rdi+0x6d],bl
  78:	61                   	(bad)  
  79:	72 6b                	jb     e6 <_init-0x69a>
  7b:	65 72 73             	gs jb  f1 <_init-0x68f>
  7e:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
  81:	4f 5f                	rex.WRXB pop r15
  83:	72 65                	jb     ea <_init-0x696>
  85:	61                   	(bad)  
  86:	64 5f                	fs pop rdi
  88:	65 6e                	outs   dx,BYTE PTR gs:[rsi]
  8a:	64 00 5f 49          	add    BYTE PTR fs:[rdi+0x49],bl
  8e:	4f 5f                	rex.WRXB pop r15
  90:	77 72                	ja     104 <_init-0x67c>
  92:	69 74 65 5f 62 61 73 	imul   esi,DWORD PTR [rbp+riz*2+0x5f],0x65736162
  99:	65 
  9a:	00 73 74             	add    BYTE PTR [rbx+0x74],dh
  9d:	64 65 72 72          	fs gs jb 113 <_init-0x66d>
  a1:	00 6c 6f 6e          	add    BYTE PTR [rdi+rbp*2+0x6e],ch
  a5:	67 20 6c 6f 6e       	and    BYTE PTR [edi+ebp*2+0x6e],ch
  aa:	67 20 69 6e          	and    BYTE PTR [ecx+0x6e],ch
  ae:	74 00                	je     b0 <_init-0x6d0>
  b0:	5f                   	pop    rdi
  b1:	5f                   	pop    rdi
  b2:	74 69                	je     11d <_init-0x663>
  b4:	6d                   	ins    DWORD PTR es:[rdi],dx
  b5:	65 7a 6f             	gs jp  127 <_init-0x659>
  b8:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  b9:	65 00 5f 6c          	add    BYTE PTR gs:[rdi+0x6c],bl
  bd:	6f                   	outs   dx,DWORD PTR ds:[rsi]
  be:	63 6b 00             	movsxd ebp,DWORD PTR [rbx+0x0]
  c1:	5f                   	pop    rdi
  c2:	5f                   	pop    rdi
  c3:	64 61                	fs (bad) 
  c5:	79 6c                	jns    133 <_init-0x64d>
  c7:	69 67 68 74 00 5f 63 	imul   esp,DWORD PTR [rdi+0x68],0x635f0074
  ce:	75 72                	jne    142 <_init-0x63e>
  d0:	5f                   	pop    rdi
  d1:	63 6f 6c             	movsxd ebp,DWORD PTR [rdi+0x6c]
  d4:	75 6d                	jne    143 <_init-0x63d>
  d6:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  d7:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
  da:	4f 5f                	rex.WRXB pop r15
  dc:	32 5f 31             	xor    bl,BYTE PTR [rdi+0x31]
  df:	5f                   	pop    rdi
  e0:	73 74                	jae    156 <_init-0x62a>
  e2:	64 65 72 72          	fs gs jb 158 <_init-0x628>
  e6:	5f                   	pop    rdi
  e7:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
  ea:	4f 5f                	rex.WRXB pop r15
  ec:	46                   	rex.RX
  ed:	49                   	rex.WB
  ee:	4c                   	rex.WR
  ef:	45 5f                	rex.RB pop r15
  f1:	70 6c                	jo     15f <_init-0x621>
  f3:	75 73                	jne    168 <_init-0x618>
  f5:	00 5f 70             	add    BYTE PTR [rdi+0x70],bl
  f8:	6f                   	outs   dx,DWORD PTR ds:[rsi]
  f9:	73 00                	jae    fb <_init-0x685>
  fb:	5f                   	pop    rdi
  fc:	73 62                	jae    160 <_init-0x620>
  fe:	75 66                	jne    166 <_init-0x61a>
 100:	00 5f 6f             	add    BYTE PTR [rdi+0x6f],bl
 103:	6c                   	ins    BYTE PTR es:[rdi],dx
 104:	64 5f                	fs pop rdi
 106:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 107:	66 66 73 65          	data16 data16 jae 170 <_init-0x610>
 10b:	74 00                	je     10d <_init-0x673>
 10d:	75 6e                	jne    17d <_init-0x603>
 10f:	73 69                	jae    17a <_init-0x606>
 111:	67 6e                	outs   dx,BYTE PTR ds:[esi]
 113:	65 64 20 63 68       	gs and BYTE PTR fs:[rbx+0x68],ah
 118:	61                   	(bad)  
 119:	72 00                	jb     11b <_init-0x665>
 11b:	6c                   	ins    BYTE PTR es:[rdi],dx
 11c:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 11d:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 11e:	67 20 6c 6f 6e       	and    BYTE PTR [edi+ebp*2+0x6e],ch
 123:	67 20 75 6e          	and    BYTE PTR [ebp+0x6e],dh
 127:	73 69                	jae    192 <_init-0x5ee>
 129:	67 6e                	outs   dx,BYTE PTR ds:[esi]
 12b:	65 64 20 69 6e       	gs and BYTE PTR fs:[rcx+0x6e],ch
 130:	74 00                	je     132 <_init-0x64e>
 132:	5f                   	pop    rdi
 133:	49                   	rex.WB
 134:	4f 5f                	rex.WRXB pop r15
 136:	32 5f 31             	xor    bl,BYTE PTR [rdi+0x31]
 139:	5f                   	pop    rdi
 13a:	73 74                	jae    1b0 <_init-0x5d0>
 13c:	64 69 6e 5f 00 5f 49 	imul   ebp,DWORD PTR fs:[rsi+0x5f],0x4f495f00
 143:	4f 
 144:	5f                   	pop    rdi
 145:	6d                   	ins    DWORD PTR es:[rdi],dx
 146:	61                   	(bad)  
 147:	72 6b                	jb     1b4 <_init-0x5cc>
 149:	65 72 00             	gs jb  14c <_init-0x634>
 14c:	5f                   	pop    rdi
 14d:	73 68                	jae    1b7 <_init-0x5c9>
 14f:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 150:	72 74                	jb     1c6 <_init-0x5ba>
 152:	62                   	(bad)  
 153:	75 66                	jne    1bb <_init-0x5c5>
 155:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
 158:	70 61                	jo     1bb <_init-0x5c5>
 15a:	64 31 00             	xor    DWORD PTR fs:[rax],eax
 15d:	5f                   	pop    rdi
 15e:	75 6e                	jne    1ce <_init-0x5b2>
 160:	75 73                	jne    1d5 <_init-0x5ab>
 162:	65 64 32 00          	gs xor al,BYTE PTR fs:[rax]
 166:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 167:	70 74                	jo     1dd <_init-0x5a3>
 169:	65 72 72             	gs jb  1de <_init-0x5a2>
 16c:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
 16f:	4f 5f                	rex.WRXB pop r15
 171:	62                   	(bad)  
 172:	75 66                	jne    1da <_init-0x5a6>
 174:	5f                   	pop    rdi
 175:	65 6e                	outs   dx,BYTE PTR gs:[rsi]
 177:	64 00 6d 61          	add    BYTE PTR fs:[rbp+0x61],ch
 17b:	69 6e 00 5f 6e 65 78 	imul   ebp,DWORD PTR [rsi+0x0],0x78656e5f
 182:	74 00                	je     184 <_init-0x5fc>
 184:	61                   	(bad)  
 185:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 186:	73 77                	jae    1ff <_init-0x581>
 188:	65 72 00             	gs jb  18b <_init-0x5f5>
 18b:	5f                   	pop    rdi
 18c:	5f                   	pop    rdi
 18d:	70 61                	jo     1f0 <_init-0x590>
 18f:	64 32 00             	xor    al,BYTE PTR fs:[rax]
 192:	5f                   	pop    rdi
 193:	5f                   	pop    rdi
 194:	70 61                	jo     1f7 <_init-0x589>
 196:	64 33 00             	xor    eax,DWORD PTR fs:[rax]
 199:	5f                   	pop    rdi
 19a:	5f                   	pop    rdi
 19b:	70 61                	jo     1fe <_init-0x582>
 19d:	64 34 00             	fs xor al,0x0
 1a0:	5f                   	pop    rdi
 1a1:	5f                   	pop    rdi
 1a2:	70 61                	jo     205 <_init-0x57b>
 1a4:	64 35 00 73 68 6f    	fs xor eax,0x6f687300
 1aa:	72 74                	jb     220 <_init-0x560>
 1ac:	20 75 6e             	and    BYTE PTR [rbp+0x6e],dh
 1af:	73 69                	jae    21a <_init-0x566>
 1b1:	67 6e                	outs   dx,BYTE PTR ds:[esi]
 1b3:	65 64 20 69 6e       	gs and BYTE PTR fs:[rcx+0x6e],ch
 1b8:	74 00                	je     1ba <_init-0x5c6>
 1ba:	5f                   	pop    rdi
 1bb:	49                   	rex.WB
 1bc:	4f 5f                	rex.WRXB pop r15
 1be:	77 72                	ja     232 <_init-0x54e>
 1c0:	69 74 65 5f 65 6e 64 	imul   esi,DWORD PTR [rbp+riz*2+0x5f],0x646e65
 1c7:	00 
 1c8:	5f                   	pop    rdi
 1c9:	5f                   	pop    rdi
 1ca:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 1cb:	66 66 36 34 5f       	data16 data16 ss xor al,0x5f
 1d0:	74 00                	je     1d2 <_init-0x5ae>
 1d2:	5f                   	pop    rdi
 1d3:	66 69 6c 65 6e 6f 00 	imul   bp,WORD PTR [rbp+riz*2+0x6e],0x6f
 1da:	5f                   	pop    rdi
 1db:	63 68 61             	movsxd ebp,DWORD PTR [rax+0x61]
 1de:	69 6e 00 2f 68 6f 6d 	imul   ebp,DWORD PTR [rsi+0x0],0x6d6f682f
 1e5:	65 2f                	gs (bad) 
 1e7:	68 75 61 6e 67       	push   0x676e6175
 1ec:	61                   	(bad)  
 1ed:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 1ee:	74 2f                	je     21f <_init-0x561>
 1f0:	6d                   	ins    DWORD PTR es:[rdi],dx
 1f1:	79 70                	jns    263 <_init-0x51d>
 1f3:	72 6f                	jb     264 <_init-0x51c>
 1f5:	67 2f                	addr32 (bad) 
 1f7:	75 6e                	jne    267 <_init-0x519>
 1f9:	69 78 5f 70 72 6f 67 	imul   edi,DWORD PTR [rax+0x5f],0x676f7270
 200:	2f                   	(bad)  
 201:	70 72                	jo     275 <_init-0x50b>
 203:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 204:	63 65 6e             	movsxd esp,DWORD PTR [rbp+0x6e]
 207:	76 00                	jbe    209 <_init-0x577>
 209:	47                   	rex.RXB
 20a:	4e 55                	rex.WRX push rbp
 20c:	20 43 31             	and    BYTE PTR [rbx+0x31],al
 20f:	31 20                	xor    DWORD PTR [rax],esp
 211:	37                   	(bad)  
 212:	2e 35 2e 30 20 2d    	cs xor eax,0x2d20302e
 218:	6d                   	ins    DWORD PTR es:[rdi],dx
 219:	74 75                	je     290 <_init-0x4f0>
 21b:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 21c:	65 3d 67 65 6e 65    	gs cmp eax,0x656e6567
 222:	72 69                	jb     28d <_init-0x4f3>
 224:	63 20                	movsxd esp,DWORD PTR [rax]
 226:	2d 6d 61 72 63       	sub    eax,0x6372616d
 22b:	68 3d 78 38 36       	push   0x3638783d
 230:	2d 36 34 20 2d       	sub    eax,0x2d203436
 235:	67 20 2d 66 73 74 61 	and    BYTE PTR [eip+0x61747366],ch        # 617475a2 <_end+0x61546572>
 23c:	63 6b 2d             	movsxd ebp,DWORD PTR [rbx+0x2d]
 23f:	70 72                	jo     2b3 <_init-0x4cd>
 241:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 242:	74 65                	je     2a9 <_init-0x4d7>
 244:	63 74 6f 72          	movsxd esi,DWORD PTR [rdi+rbp*2+0x72]
 248:	2d 73 74 72 6f       	sub    eax,0x6f727473
 24d:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 24e:	67 00 5f 49          	add    BYTE PTR [edi+0x49],bl
 252:	4f 5f                	rex.WRXB pop r15
 254:	62 61                	(bad)  
 256:	63 6b 75             	movsxd ebp,DWORD PTR [rbx+0x75]
 259:	70 5f                	jo     2ba <_init-0x4c6>
 25b:	62 61                	(bad)  
 25d:	73 65                	jae    2c4 <_init-0x4bc>
 25f:	00 73 74             	add    BYTE PTR [rbx+0x74],dh
 262:	64 69 6e 00 5f 49 4f 	imul   ebp,DWORD PTR fs:[rsi+0x0],0x5f4f495f
 269:	5f 
 26a:	62                   	(bad)  
 26b:	75 66                	jne    2d3 <_init-0x4ad>
 26d:	5f                   	pop    rdi
 26e:	62 61                	(bad)  
 270:	73 65                	jae    2d7 <_init-0x4a9>
 272:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
 275:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 276:	66 66 5f             	data16 pop di
 279:	74 00                	je     27b <_init-0x505>
 27b:	5f                   	pop    rdi
 27c:	66 6c                	data16 ins BYTE PTR es:[rdi],dx
 27e:	61                   	(bad)  
 27f:	67 73 32             	addr32 jae 2b4 <_init-0x4cc>
 282:	00 5f 6d             	add    BYTE PTR [rdi+0x6d],bl
 285:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 286:	64 65 00 5f 49       	fs add BYTE PTR gs:[rdi+0x49],bl
 28b:	4f 5f                	rex.WRXB pop r15
 28d:	72 65                	jb     2f4 <_init-0x48c>
 28f:	61                   	(bad)  
 290:	64 5f                	fs pop rdi
 292:	62 61                	(bad)  
 294:	73 65                	jae    2fb <_init-0x485>
 296:	00 5f 76             	add    BYTE PTR [rdi+0x76],bl
 299:	74 61                	je     2fc <_init-0x484>
 29b:	62                   	(bad)  
 29c:	6c                   	ins    BYTE PTR es:[rdi],dx
 29d:	65 5f                	gs pop rdi
 29f:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 2a0:	66 66 73 65          	data16 data16 jae 309 <_init-0x477>
 2a4:	74 00                	je     2a6 <_init-0x4da>
 2a6:	5f                   	pop    rdi
 2a7:	49                   	rex.WB
 2a8:	4f 5f                	rex.WRXB pop r15
 2aa:	73 61                	jae    30d <_init-0x473>
 2ac:	76 65                	jbe    313 <_init-0x46d>
 2ae:	5f                   	pop    rdi
 2af:	62 61                	(bad)  
 2b1:	73 65                	jae    318 <_init-0x468>
 2b3:	00 73 79             	add    BYTE PTR [rbx+0x79],dh
 2b6:	73 5f                	jae    317 <_init-0x469>
 2b8:	65 72 72             	gs jb  32d <_init-0x453>
 2bb:	6c                   	ins    BYTE PTR es:[rdi],dx
 2bc:	69 73 74 00 6f 70 74 	imul   esi,DWORD PTR [rbx+0x74],0x74706f00
 2c3:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 2c4:	70 74                	jo     33a <_init-0x446>
 2c6:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
 2c9:	4f 5f                	rex.WRXB pop r15
 2cb:	72 65                	jb     332 <_init-0x44e>
 2cd:	61                   	(bad)  
 2ce:	64 5f                	fs pop rdi
 2d0:	70 74                	jo     346 <_init-0x43a>
 2d2:	72 00                	jb     2d4 <_init-0x4ac>
 2d4:	67 75 65             	addr32 jne 33c <_init-0x444>
 2d7:	73 73                	jae    34c <_init-0x434>
 2d9:	2e 63 00             	movsxd eax,DWORD PTR cs:[rax]
 2dc:	73 74                	jae    352 <_init-0x42e>
 2de:	64 6f                	outs   dx,DWORD PTR fs:[rsi]
 2e0:	75 74                	jne    356 <_init-0x42a>
 2e2:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
 2e5:	4f 5f                	rex.WRXB pop r15
 2e7:	6c                   	ins    BYTE PTR es:[rdi],dx
 2e8:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 2e9:	63 6b 5f             	movsxd ebp,DWORD PTR [rbx+0x5f]
 2ec:	74 00                	je     2ee <_init-0x492>
