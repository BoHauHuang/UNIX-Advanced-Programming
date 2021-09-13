
got_magic:     file format elf64-x86-64


Disassembly of section .interp:

0000000000000238 <.interp>:
 238:	2f                   	(bad)  
 239:	6c                   	ins    BYTE PTR es:[rdi],dx
 23a:	69 62 36 34 2f 6c 64 	imul   esp,DWORD PTR [rdx+0x36],0x646c2f34
 241:	2d 6c 69 6e 75       	sub    eax,0x756e696c
 246:	78 2d                	js     275 <_init-0x663>
 248:	78 38                	js     282 <_init-0x656>
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
 283:	00 a6 5f e7 f8 1f    	add    BYTE PTR [rsi+0x1ff8e75f],ah
 289:	3b a4 fb 58 ac f7 04 	cmp    esp,DWORD PTR [rbx+rdi*8+0x4f7ac58]
 290:	22 12                	and    dl,BYTE PTR [rdx]
 292:	38 1d 22 f9 b9 86    	cmp    BYTE PTR [rip+0xffffffff86b9f922],bl        # ffffffff86b9fbba <_end+0xffffffff8699daea>

Disassembly of section .gnu.hash:

0000000000000298 <.gnu.hash>:
 298:	03 00                	add    eax,DWORD PTR [rax]
 29a:	00 00                	add    BYTE PTR [rax],al
 29c:	15 00 00 00 01       	adc    eax,0x1000000
 2a1:	00 00                	add    BYTE PTR [rax],al
 2a3:	00 06                	add    BYTE PTR [rsi],al
 2a5:	00 00                	add    BYTE PTR [rax],al
 2a7:	00 00                	add    BYTE PTR [rax],al
 2a9:	01 20                	add    DWORD PTR [rax],esp
 2ab:	00 80 01 10 02 15    	add    BYTE PTR [rax+0x15021001],al
 2b1:	00 00                	add    BYTE PTR [rax],al
 2b3:	00 16                	add    BYTE PTR [rsi],dl
 2b5:	00 00                	add    BYTE PTR [rax],al
 2b7:	00 00                	add    BYTE PTR [rax],al
 2b9:	00 00                	add    BYTE PTR [rax],al
 2bb:	00 29                	add    BYTE PTR [rcx],ch
 2bd:	1d 8c 1c 66 55       	sbb    eax,0x55661c8c
 2c2:	61                   	(bad)  
 2c3:	10 39                	adc    BYTE PTR [rcx],bh
 2c5:	f2                   	repnz
 2c6:	8b                   	.byte 0x8b
 2c7:	1c                   	.byte 0x1c

Disassembly of section .dynsym:

00000000000002c8 <.dynsym>:
	...
 2e0:	b7 00                	mov    bh,0x0
 2e2:	00 00                	add    BYTE PTR [rax],al
 2e4:	20 00                	and    BYTE PTR [rax],al
	...
 2f6:	00 00                	add    BYTE PTR [rax],al
 2f8:	27                   	(bad)  
 2f9:	00 00                	add    BYTE PTR [rax],al
 2fb:	00 12                	add    BYTE PTR [rdx],dl
	...
 30d:	00 00                	add    BYTE PTR [rax],al
 30f:	00 0b                	add    BYTE PTR [rbx],cl
 311:	00 00                	add    BYTE PTR [rax],al
 313:	00 12                	add    BYTE PTR [rdx],dl
	...
 325:	00 00                	add    BYTE PTR [rax],al
 327:	00 55 00             	add    BYTE PTR [rbp+0x0],dl
 32a:	00 00                	add    BYTE PTR [rax],al
 32c:	12 00                	adc    al,BYTE PTR [rax]
	...
 33e:	00 00                	add    BYTE PTR [rax],al
 340:	92                   	xchg   edx,eax
 341:	00 00                	add    BYTE PTR [rax],al
 343:	00 12                	add    BYTE PTR [rdx],dl
	...
 355:	00 00                	add    BYTE PTR [rax],al
 357:	00 10                	add    BYTE PTR [rax],dl
 359:	00 00                	add    BYTE PTR [rax],al
 35b:	00 12                	add    BYTE PTR [rdx],dl
	...
 36d:	00 00                	add    BYTE PTR [rax],al
 36f:	00 9a 00 00 00 12    	add    BYTE PTR [rdx+0x12000000],bl
	...
 385:	00 00                	add    BYTE PTR [rax],al
 387:	00 98 00 00 00 12    	add    BYTE PTR [rax+0x12000000],bl
	...
 39d:	00 00                	add    BYTE PTR [rax],al
 39f:	00 3a                	add    BYTE PTR [rdx],bh
 3a1:	00 00                	add    BYTE PTR [rax],al
 3a3:	00 12                	add    BYTE PTR [rdx],dl
	...
 3b5:	00 00                	add    BYTE PTR [rax],al
 3b7:	00 5e 00             	add    BYTE PTR [rsi+0x0],bl
 3ba:	00 00                	add    BYTE PTR [rax],al
 3bc:	12 00                	adc    al,BYTE PTR [rax]
	...
 3ce:	00 00                	add    BYTE PTR [rax],al
 3d0:	42 00 00             	rex.X add BYTE PTR [rax],al
 3d3:	00 12                	add    BYTE PTR [rdx],dl
	...
 3e5:	00 00                	add    BYTE PTR [rax],al
 3e7:	00 80 00 00 00 12    	add    BYTE PTR [rax+0x12000000],al
	...
 3fd:	00 00                	add    BYTE PTR [rax],al
 3ff:	00 34 00             	add    BYTE PTR [rax+rax*1],dh
 402:	00 00                	add    BYTE PTR [rax],al
 404:	12 00                	adc    al,BYTE PTR [rax]
	...
 416:	00 00                	add    BYTE PTR [rax],al
 418:	d3 00                	rol    DWORD PTR [rax],cl
 41a:	00 00                	add    BYTE PTR [rax],al
 41c:	20 00                	and    BYTE PTR [rax],al
	...
 42e:	00 00                	add    BYTE PTR [rax],al
 430:	2d 00 00 00 12       	sub    eax,0x12000000
	...
 445:	00 00                	add    BYTE PTR [rax],al
 447:	00 78 00             	add    BYTE PTR [rax+0x0],bh
 44a:	00 00                	add    BYTE PTR [rax],al
 44c:	12 00                	adc    al,BYTE PTR [rax]
	...
 45e:	00 00                	add    BYTE PTR [rax],al
 460:	64 00 00             	add    BYTE PTR fs:[rax],al
 463:	00 12                	add    BYTE PTR [rdx],dl
	...
 475:	00 00                	add    BYTE PTR [rax],al
 477:	00 28                	add    BYTE PTR [rax],ch
 479:	00 00                	add    BYTE PTR [rax],al
 47b:	00 12                	add    BYTE PTR [rdx],dl
	...
 48d:	00 00                	add    BYTE PTR [rax],al
 48f:	00 e2                	add    dl,ah
 491:	00 00                	add    BYTE PTR [rax],al
 493:	00 20                	add    BYTE PTR [rax],ah
	...
 4a5:	00 00                	add    BYTE PTR [rax],al
 4a7:	00 69 00             	add    BYTE PTR [rcx+0x0],ch
 4aa:	00 00                	add    BYTE PTR [rax],al
 4ac:	22 00                	and    al,BYTE PTR [rax]
	...
 4be:	00 00                	add    BYTE PTR [rax],al
 4c0:	47 00 00             	rex.RXB add BYTE PTR [r8],r8b
 4c3:	00 11                	add    BYTE PTR [rcx],dl
 4c5:	00 19                	add    BYTE PTR [rcx],bl
 4c7:	00 a0 20 20 00 00    	add    BYTE PTR [rax+0x2020],ah
 4cd:	00 00                	add    BYTE PTR [rax],al
 4cf:	00 08                	add    BYTE PTR [rax],cl
 4d1:	00 00                	add    BYTE PTR [rax],al
 4d3:	00 00                	add    BYTE PTR [rax],al
 4d5:	00 00                	add    BYTE PTR [rax],al
 4d7:	00 21                	add    BYTE PTR [rcx],ah
 4d9:	00 00                	add    BYTE PTR [rax],al
 4db:	00 11                	add    BYTE PTR [rcx],dl
 4dd:	00 19                	add    BYTE PTR [rcx],bl
 4df:	00 b0 20 20 00 00    	add    BYTE PTR [rax+0x2020],dh
 4e5:	00 00                	add    BYTE PTR [rax],al
 4e7:	00 08                	add    BYTE PTR [rax],cl
 4e9:	00 00                	add    BYTE PTR [rax],al
 4eb:	00 00                	add    BYTE PTR [rax],al
 4ed:	00 00                	add    BYTE PTR [rax],al
 4ef:	00 4e 00             	add    BYTE PTR [rsi+0x0],cl
 4f2:	00 00                	add    BYTE PTR [rax],al
 4f4:	11 00                	adc    DWORD PTR [rax],eax
 4f6:	19 00                	sbb    DWORD PTR [rax],eax
 4f8:	c0 20 20             	shl    BYTE PTR [rax],0x20
 4fb:	00 00                	add    BYTE PTR [rax],al
 4fd:	00 00                	add    BYTE PTR [rax],al
 4ff:	00 08                	add    BYTE PTR [rax],cl
 501:	00 00                	add    BYTE PTR [rax],al
 503:	00 00                	add    BYTE PTR [rax],al
 505:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .dynstr:

0000000000000508 <.dynstr>:
 508:	00 6c 69 62          	add    BYTE PTR [rcx+rbp*2+0x62],ch
 50c:	63 2e                	movsxd ebp,DWORD PTR [rsi]
 50e:	73 6f                	jae    57f <_init-0x359>
 510:	2e 36 00 70 75       	cs add BYTE PTR ss:[rax+0x75],dh
 515:	74 73                	je     58a <_init-0x34e>
 517:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
 51a:	73 74                	jae    590 <_init-0x348>
 51c:	61                   	(bad)  
 51d:	63 6b 5f             	movsxd ebp,DWORD PTR [rbx+0x5f]
 520:	63 68 6b             	movsxd ebp,DWORD PTR [rax+0x6b]
 523:	5f                   	pop    rdi
 524:	66 61                	data16 (bad) 
 526:	69 6c 00 73 74 64 69 	imul   ebp,DWORD PTR [rax+rax*1+0x73],0x6e696474
 52d:	6e 
 52e:	00 5f 65             	add    BYTE PTR [rdi+0x65],bl
 531:	78 69                	js     59c <_init-0x33c>
 533:	74 00                	je     535 <_init-0x3a3>
 535:	73 74                	jae    5ab <_init-0x32d>
 537:	72 74                	jb     5ad <_init-0x32b>
 539:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 53a:	6c                   	ins    BYTE PTR es:[rdi],dx
 53b:	00 66 67             	add    BYTE PTR [rsi+0x67],ah
 53e:	65 74 73             	gs je  5b4 <_init-0x324>
 541:	00 64 69 72          	add    BYTE PTR [rcx+rbp*2+0x72],ah
 545:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 546:	61                   	(bad)  
 547:	6d                   	ins    DWORD PTR es:[rdi],dx
 548:	65 00 72 65          	add    BYTE PTR gs:[rdx+0x65],dh
 54c:	61                   	(bad)  
 54d:	64 00 73 74          	add    BYTE PTR fs:[rbx+0x74],dh
 551:	64 6f                	outs   dx,DWORD PTR fs:[rsi]
 553:	75 74                	jne    5c9 <_init-0x30f>
 555:	00 73 74             	add    BYTE PTR [rbx+0x74],dh
 558:	64 65 72 72          	fs gs jb 5ce <_init-0x30a>
 55c:	00 72 65             	add    BYTE PTR [rdx+0x65],dh
 55f:	61                   	(bad)  
 560:	64 6c                	fs ins BYTE PTR es:[rdi],dx
 562:	69 6e 6b 00 63 6c 6f 	imul   ebp,DWORD PTR [rsi+0x6b],0x6f6c6300
 569:	73 65                	jae    5d0 <_init-0x308>
 56b:	00 6f 70             	add    BYTE PTR [rdi+0x70],ch
 56e:	65 6e                	outs   dx,BYTE PTR gs:[rsi]
 570:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
 573:	63 78 61             	movsxd edi,DWORD PTR [rax+0x61]
 576:	5f                   	pop    rdi
 577:	66 69 6e 61 6c 69    	imul   bp,WORD PTR [rsi+0x61],0x696c
 57d:	7a 65                	jp     5e4 <_init-0x2f4>
 57f:	00 73 65             	add    BYTE PTR [rbx+0x65],dh
 582:	74 76                	je     5fa <_init-0x2de>
 584:	62                   	(bad)  
 585:	75 66                	jne    5ed <_init-0x2eb>
 587:	00 5f 5f             	add    BYTE PTR [rdi+0x5f],bl
 58a:	6c                   	ins    BYTE PTR es:[rdi],dx
 58b:	69 62 63 5f 73 74 61 	imul   esp,DWORD PTR [rdx+0x63],0x6174735f
 592:	72 74                	jb     608 <_init-0x2d0>
 594:	5f                   	pop    rdi
 595:	6d                   	ins    DWORD PTR es:[rdi],dx
 596:	61                   	(bad)  
 597:	69 6e 00 77 72 69 74 	imul   ebp,DWORD PTR [rsi+0x0],0x74697277
 59e:	65 00 73 6e          	add    BYTE PTR gs:[rbx+0x6e],dh
 5a2:	70 72                	jo     616 <_init-0x2c2>
 5a4:	69 6e 74 66 00 47 4c 	imul   ebp,DWORD PTR [rsi+0x74],0x4c470066
 5ab:	49                   	rex.WB
 5ac:	42                   	rex.X
 5ad:	43 5f                	rex.XB pop r15
 5af:	32 2e                	xor    ch,BYTE PTR [rsi]
 5b1:	34 00                	xor    al,0x0
 5b3:	47                   	rex.RXB
 5b4:	4c                   	rex.WR
 5b5:	49                   	rex.WB
 5b6:	42                   	rex.X
 5b7:	43 5f                	rex.XB pop r15
 5b9:	32 2e                	xor    ch,BYTE PTR [rsi]
 5bb:	32 2e                	xor    ch,BYTE PTR [rsi]
 5bd:	35 00 5f 49 54       	xor    eax,0x54495f00
 5c2:	4d 5f                	rex.WRB pop r15
 5c4:	64 65 72 65          	fs gs jb 62d <_init-0x2ab>
 5c8:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
 5cf:	4d 
 5d0:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
 5d2:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 5d3:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 5d4:	65 54                	gs push rsp
 5d6:	61                   	(bad)  
 5d7:	62                   	(bad)  
 5d8:	6c                   	ins    BYTE PTR es:[rdi],dx
 5d9:	65 00 5f 5f          	add    BYTE PTR gs:[rdi+0x5f],bl
 5dd:	67 6d                	ins    DWORD PTR es:[edi],dx
 5df:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 5e0:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 5e1:	5f                   	pop    rdi
 5e2:	73 74                	jae    658 <_init-0x280>
 5e4:	61                   	(bad)  
 5e5:	72 74                	jb     65b <_init-0x27d>
 5e7:	5f                   	pop    rdi
 5e8:	5f                   	pop    rdi
 5e9:	00 5f 49             	add    BYTE PTR [rdi+0x49],bl
 5ec:	54                   	push   rsp
 5ed:	4d 5f                	rex.WRB pop r15
 5ef:	72 65                	jb     656 <_init-0x282>
 5f1:	67 69 73 74 65 72 54 	imul   esi,DWORD PTR [ebx+0x74],0x4d547265
 5f8:	4d 
 5f9:	43 6c                	rex.XB ins BYTE PTR es:[rdi],dx
 5fb:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 5fc:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 5fd:	65 54                	gs push rsp
 5ff:	61                   	(bad)  
 600:	62                   	.byte 0x62
 601:	6c                   	ins    BYTE PTR es:[rdi],dx
 602:	65                   	gs
	...

Disassembly of section .gnu.version:

0000000000000604 <.gnu.version>:
 604:	00 00                	add    BYTE PTR [rax],al
 606:	00 00                	add    BYTE PTR [rax],al
 608:	02 00                	add    al,BYTE PTR [rax]
 60a:	02 00                	add    al,BYTE PTR [rax]
 60c:	02 00                	add    al,BYTE PTR [rax]
 60e:	02 00                	add    al,BYTE PTR [rax]
 610:	03 00                	add    eax,DWORD PTR [rax]
 612:	02 00                	add    al,BYTE PTR [rax]
 614:	02 00                	add    al,BYTE PTR [rax]
 616:	02 00                	add    al,BYTE PTR [rax]
 618:	02 00                	add    al,BYTE PTR [rax]
 61a:	02 00                	add    al,BYTE PTR [rax]
 61c:	02 00                	add    al,BYTE PTR [rax]
 61e:	02 00                	add    al,BYTE PTR [rax]
 620:	00 00                	add    BYTE PTR [rax],al
 622:	02 00                	add    al,BYTE PTR [rax]
 624:	02 00                	add    al,BYTE PTR [rax]
 626:	02 00                	add    al,BYTE PTR [rax]
 628:	02 00                	add    al,BYTE PTR [rax]
 62a:	00 00                	add    BYTE PTR [rax],al
 62c:	02 00                	add    al,BYTE PTR [rax]
 62e:	02 00                	add    al,BYTE PTR [rax]
 630:	02 00                	add    al,BYTE PTR [rax]
 632:	02 00                	add    al,BYTE PTR [rax]

Disassembly of section .gnu.version_r:

0000000000000638 <.gnu.version_r>:
 638:	01 00                	add    DWORD PTR [rax],eax
 63a:	02 00                	add    al,BYTE PTR [rax]
 63c:	01 00                	add    DWORD PTR [rax],eax
 63e:	00 00                	add    BYTE PTR [rax],al
 640:	10 00                	adc    BYTE PTR [rax],al
 642:	00 00                	add    BYTE PTR [rax],al
 644:	00 00                	add    BYTE PTR [rax],al
 646:	00 00                	add    BYTE PTR [rax],al
 648:	14 69                	adc    al,0x69
 64a:	69 0d 00 00 03 00 a1 	imul   ecx,DWORD PTR [rip+0x30000],0xa1        # 30654 <__FRAME_END__+0x2f610>
 651:	00 00 00 
 654:	10 00                	adc    BYTE PTR [rax],al
 656:	00 00                	add    BYTE PTR [rax],al
 658:	75 1a                	jne    674 <_init-0x264>
 65a:	69 09 00 00 02 00    	imul   ecx,DWORD PTR [rcx],0x20000
 660:	ab                   	stos   DWORD PTR es:[rdi],eax
 661:	00 00                	add    BYTE PTR [rax],al
 663:	00 00                	add    BYTE PTR [rax],al
 665:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .rela.dyn:

0000000000000668 <.rela.dyn>:
 668:	e0 1d                	loopne 687 <_init-0x251>
 66a:	20 00                	and    BYTE PTR [rax],al
 66c:	00 00                	add    BYTE PTR [rax],al
 66e:	00 00                	add    BYTE PTR [rax],al
 670:	08 00                	or     BYTE PTR [rax],al
 672:	00 00                	add    BYTE PTR [rax],al
 674:	00 00                	add    BYTE PTR [rax],al
 676:	00 00                	add    BYTE PTR [rax],al
 678:	f0 0a 00             	lock or al,BYTE PTR [rax]
 67b:	00 00                	add    BYTE PTR [rax],al
 67d:	00 00                	add    BYTE PTR [rax],al
 67f:	00 e8                	add    al,ch
 681:	1d 20 00 00 00       	sbb    eax,0x20
 686:	00 00                	add    BYTE PTR [rax],al
 688:	08 00                	or     BYTE PTR [rax],al
 68a:	00 00                	add    BYTE PTR [rax],al
 68c:	00 00                	add    BYTE PTR [rax],al
 68e:	00 00                	add    BYTE PTR [rax],al
 690:	b0 0a                	mov    al,0xa
 692:	00 00                	add    BYTE PTR [rax],al
 694:	00 00                	add    BYTE PTR [rax],al
 696:	00 00                	add    BYTE PTR [rax],al
 698:	90                   	nop
 699:	20 20                	and    BYTE PTR [rax],ah
 69b:	00 00                	add    BYTE PTR [rax],al
 69d:	00 00                	add    BYTE PTR [rax],al
 69f:	00 08                	add    BYTE PTR [rax],cl
 6a1:	00 00                	add    BYTE PTR [rax],al
 6a3:	00 00                	add    BYTE PTR [rax],al
 6a5:	00 00                	add    BYTE PTR [rax],al
 6a7:	00 90 20 20 00 00    	add    BYTE PTR [rax+0x2020],dl
 6ad:	00 00                	add    BYTE PTR [rax],al
 6af:	00 d0                	add    al,dl
 6b1:	1f                   	(bad)  
 6b2:	20 00                	and    BYTE PTR [rax],al
 6b4:	00 00                	add    BYTE PTR [rax],al
 6b6:	00 00                	add    BYTE PTR [rax],al
 6b8:	06                   	(bad)  
 6b9:	00 00                	add    BYTE PTR [rax],al
 6bb:	00 01                	add    BYTE PTR [rcx],al
	...
 6c5:	00 00                	add    BYTE PTR [rax],al
 6c7:	00 d8                	add    al,bl
 6c9:	1f                   	(bad)  
 6ca:	20 00                	and    BYTE PTR [rax],al
 6cc:	00 00                	add    BYTE PTR [rax],al
 6ce:	00 00                	add    BYTE PTR [rax],al
 6d0:	06                   	(bad)  
 6d1:	00 00                	add    BYTE PTR [rax],al
 6d3:	00 03                	add    BYTE PTR [rbx],al
	...
 6dd:	00 00                	add    BYTE PTR [rax],al
 6df:	00 e0                	add    al,ah
 6e1:	1f                   	(bad)  
 6e2:	20 00                	and    BYTE PTR [rax],al
 6e4:	00 00                	add    BYTE PTR [rax],al
 6e6:	00 00                	add    BYTE PTR [rax],al
 6e8:	06                   	(bad)  
 6e9:	00 00                	add    BYTE PTR [rax],al
 6eb:	00 0c 00             	add    BYTE PTR [rax+rax*1],cl
	...
 6f6:	00 00                	add    BYTE PTR [rax],al
 6f8:	e8 1f 20 00 00       	call   271c <__FRAME_END__+0x16d8>
 6fd:	00 00                	add    BYTE PTR [rax],al
 6ff:	00 06                	add    BYTE PTR [rsi],al
 701:	00 00                	add    BYTE PTR [rax],al
 703:	00 0e                	add    BYTE PTR [rsi],cl
	...
 70d:	00 00                	add    BYTE PTR [rax],al
 70f:	00 f0                	add    al,dh
 711:	1f                   	(bad)  
 712:	20 00                	and    BYTE PTR [rax],al
 714:	00 00                	add    BYTE PTR [rax],al
 716:	00 00                	add    BYTE PTR [rax],al
 718:	06                   	(bad)  
 719:	00 00                	add    BYTE PTR [rax],al
 71b:	00 13                	add    BYTE PTR [rbx],dl
	...
 725:	00 00                	add    BYTE PTR [rax],al
 727:	00 f8                	add    al,bh
 729:	1f                   	(bad)  
 72a:	20 00                	and    BYTE PTR [rax],al
 72c:	00 00                	add    BYTE PTR [rax],al
 72e:	00 00                	add    BYTE PTR [rax],al
 730:	06                   	(bad)  
 731:	00 00                	add    BYTE PTR [rax],al
 733:	00 14 00             	add    BYTE PTR [rax+rax*1],dl
	...
 73e:	00 00                	add    BYTE PTR [rax],al
 740:	a0 20 20 00 00 00 00 	movabs al,ds:0x500000000002020
 747:	00 05 
 749:	00 00                	add    BYTE PTR [rax],al
 74b:	00 15 00 00 00 00    	add    BYTE PTR [rip+0x0],dl        # 751 <_init-0x187>
 751:	00 00                	add    BYTE PTR [rax],al
 753:	00 00                	add    BYTE PTR [rax],al
 755:	00 00                	add    BYTE PTR [rax],al
 757:	00 b0 20 20 00 00    	add    BYTE PTR [rax+0x2020],dh
 75d:	00 00                	add    BYTE PTR [rax],al
 75f:	00 05 00 00 00 16    	add    BYTE PTR [rip+0x16000000],al        # 16000765 <_end+0x15dfe695>
	...
 76d:	00 00                	add    BYTE PTR [rax],al
 76f:	00 c0                	add    al,al
 771:	20 20                	and    BYTE PTR [rax],ah
 773:	00 00                	add    BYTE PTR [rax],al
 775:	00 00                	add    BYTE PTR [rax],al
 777:	00 05 00 00 00 17    	add    BYTE PTR [rip+0x17000000],al        # 1700077d <_end+0x16dfe6ad>
	...

Disassembly of section .rela.plt:

0000000000000788 <.rela.plt>:
 788:	18 20                	sbb    BYTE PTR [rax],ah
 78a:	20 00                	and    BYTE PTR [rax],al
 78c:	00 00                	add    BYTE PTR [rax],al
 78e:	00 00                	add    BYTE PTR [rax],al
 790:	07                   	(bad)  
 791:	00 00                	add    BYTE PTR [rax],al
 793:	00 02                	add    BYTE PTR [rdx],al
	...
 79d:	00 00                	add    BYTE PTR [rax],al
 79f:	00 20                	add    BYTE PTR [rax],ah
 7a1:	20 20                	and    BYTE PTR [rax],ah
 7a3:	00 00                	add    BYTE PTR [rax],al
 7a5:	00 00                	add    BYTE PTR [rax],al
 7a7:	00 07                	add    BYTE PTR [rdi],al
 7a9:	00 00                	add    BYTE PTR [rax],al
 7ab:	00 04 00             	add    BYTE PTR [rax+rax*1],al
	...
 7b6:	00 00                	add    BYTE PTR [rax],al
 7b8:	28 20                	sub    BYTE PTR [rax],ah
 7ba:	20 00                	and    BYTE PTR [rax],al
 7bc:	00 00                	add    BYTE PTR [rax],al
 7be:	00 00                	add    BYTE PTR [rax],al
 7c0:	07                   	(bad)  
 7c1:	00 00                	add    BYTE PTR [rax],al
 7c3:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 7c9 <_init-0x10f>
 7c9:	00 00                	add    BYTE PTR [rax],al
 7cb:	00 00                	add    BYTE PTR [rax],al
 7cd:	00 00                	add    BYTE PTR [rax],al
 7cf:	00 30                	add    BYTE PTR [rax],dh
 7d1:	20 20                	and    BYTE PTR [rax],ah
 7d3:	00 00                	add    BYTE PTR [rax],al
 7d5:	00 00                	add    BYTE PTR [rax],al
 7d7:	00 07                	add    BYTE PTR [rdi],al
 7d9:	00 00                	add    BYTE PTR [rax],al
 7db:	00 06                	add    BYTE PTR [rsi],al
	...
 7e5:	00 00                	add    BYTE PTR [rax],al
 7e7:	00 38                	add    BYTE PTR [rax],bh
 7e9:	20 20                	and    BYTE PTR [rax],ah
 7eb:	00 00                	add    BYTE PTR [rax],al
 7ed:	00 00                	add    BYTE PTR [rax],al
 7ef:	00 07                	add    BYTE PTR [rdi],al
 7f1:	00 00                	add    BYTE PTR [rax],al
 7f3:	00 07                	add    BYTE PTR [rdi],al
	...
 7fd:	00 00                	add    BYTE PTR [rax],al
 7ff:	00 40 20             	add    BYTE PTR [rax+0x20],al
 802:	20 00                	and    BYTE PTR [rax],al
 804:	00 00                	add    BYTE PTR [rax],al
 806:	00 00                	add    BYTE PTR [rax],al
 808:	07                   	(bad)  
 809:	00 00                	add    BYTE PTR [rax],al
 80b:	00 08                	add    BYTE PTR [rax],cl
	...
 815:	00 00                	add    BYTE PTR [rax],al
 817:	00 48 20             	add    BYTE PTR [rax+0x20],cl
 81a:	20 00                	and    BYTE PTR [rax],al
 81c:	00 00                	add    BYTE PTR [rax],al
 81e:	00 00                	add    BYTE PTR [rax],al
 820:	07                   	(bad)  
 821:	00 00                	add    BYTE PTR [rax],al
 823:	00 09                	add    BYTE PTR [rcx],cl
	...
 82d:	00 00                	add    BYTE PTR [rax],al
 82f:	00 50 20             	add    BYTE PTR [rax+0x20],dl
 832:	20 00                	and    BYTE PTR [rax],al
 834:	00 00                	add    BYTE PTR [rax],al
 836:	00 00                	add    BYTE PTR [rax],al
 838:	07                   	(bad)  
 839:	00 00                	add    BYTE PTR [rax],al
 83b:	00 0a                	add    BYTE PTR [rdx],cl
	...
 845:	00 00                	add    BYTE PTR [rax],al
 847:	00 58 20             	add    BYTE PTR [rax+0x20],bl
 84a:	20 00                	and    BYTE PTR [rax],al
 84c:	00 00                	add    BYTE PTR [rax],al
 84e:	00 00                	add    BYTE PTR [rax],al
 850:	07                   	(bad)  
 851:	00 00                	add    BYTE PTR [rax],al
 853:	00 0b                	add    BYTE PTR [rbx],cl
	...
 85d:	00 00                	add    BYTE PTR [rax],al
 85f:	00 60 20             	add    BYTE PTR [rax+0x20],ah
 862:	20 00                	and    BYTE PTR [rax],al
 864:	00 00                	add    BYTE PTR [rax],al
 866:	00 00                	add    BYTE PTR [rax],al
 868:	07                   	(bad)  
 869:	00 00                	add    BYTE PTR [rax],al
 86b:	00 0d 00 00 00 00    	add    BYTE PTR [rip+0x0],cl        # 871 <_init-0x67>
 871:	00 00                	add    BYTE PTR [rax],al
 873:	00 00                	add    BYTE PTR [rax],al
 875:	00 00                	add    BYTE PTR [rax],al
 877:	00 68 20             	add    BYTE PTR [rax+0x20],ch
 87a:	20 00                	and    BYTE PTR [rax],al
 87c:	00 00                	add    BYTE PTR [rax],al
 87e:	00 00                	add    BYTE PTR [rax],al
 880:	07                   	(bad)  
 881:	00 00                	add    BYTE PTR [rax],al
 883:	00 0f                	add    BYTE PTR [rdi],cl
	...
 88d:	00 00                	add    BYTE PTR [rax],al
 88f:	00 70 20             	add    BYTE PTR [rax+0x20],dh
 892:	20 00                	and    BYTE PTR [rax],al
 894:	00 00                	add    BYTE PTR [rax],al
 896:	00 00                	add    BYTE PTR [rax],al
 898:	07                   	(bad)  
 899:	00 00                	add    BYTE PTR [rax],al
 89b:	00 10                	add    BYTE PTR [rax],dl
	...
 8a5:	00 00                	add    BYTE PTR [rax],al
 8a7:	00 78 20             	add    BYTE PTR [rax+0x20],bh
 8aa:	20 00                	and    BYTE PTR [rax],al
 8ac:	00 00                	add    BYTE PTR [rax],al
 8ae:	00 00                	add    BYTE PTR [rax],al
 8b0:	07                   	(bad)  
 8b1:	00 00                	add    BYTE PTR [rax],al
 8b3:	00 11                	add    BYTE PTR [rcx],dl
	...
 8bd:	00 00                	add    BYTE PTR [rax],al
 8bf:	00 80 20 20 00 00    	add    BYTE PTR [rax+0x2020],al
 8c5:	00 00                	add    BYTE PTR [rax],al
 8c7:	00 07                	add    BYTE PTR [rdi],al
 8c9:	00 00                	add    BYTE PTR [rax],al
 8cb:	00 12                	add    BYTE PTR [rdx],dl
	...

Disassembly of section .init:

00000000000008d8 <_init>:
 8d8:	48 83 ec 08          	sub    rsp,0x8
 8dc:	48 8b 05 05 17 20 00 	mov    rax,QWORD PTR [rip+0x201705]        # 201fe8 <__gmon_start__>
 8e3:	48 85 c0             	test   rax,rax
 8e6:	74 02                	je     8ea <_init+0x12>
 8e8:	ff d0                	call   rax
 8ea:	48 83 c4 08          	add    rsp,0x8
 8ee:	c3                   	ret    

Disassembly of section .plt:

00000000000008f0 <.plt>:
 8f0:	ff 35 12 17 20 00    	push   QWORD PTR [rip+0x201712]        # 202008 <_GLOBAL_OFFSET_TABLE_+0x8>
 8f6:	ff 25 14 17 20 00    	jmp    QWORD PTR [rip+0x201714]        # 202010 <_GLOBAL_OFFSET_TABLE_+0x10>
 8fc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000000900 <_exit@plt>:
 900:	ff 25 12 17 20 00    	jmp    QWORD PTR [rip+0x201712]        # 202018 <_exit@GLIBC_2.2.5>
 906:	68 00 00 00 00       	push   0x0
 90b:	e9 e0 ff ff ff       	jmp    8f0 <.plt>

0000000000000910 <readlink@plt>:
 910:	ff 25 0a 17 20 00    	jmp    QWORD PTR [rip+0x20170a]        # 202020 <readlink@GLIBC_2.2.5>
 916:	68 01 00 00 00       	push   0x1
 91b:	e9 d0 ff ff ff       	jmp    8f0 <.plt>

0000000000000920 <write@plt>:
 920:	ff 25 02 17 20 00    	jmp    QWORD PTR [rip+0x201702]        # 202028 <write@GLIBC_2.2.5>
 926:	68 02 00 00 00       	push   0x2
 92b:	e9 c0 ff ff ff       	jmp    8f0 <.plt>

0000000000000930 <__stack_chk_fail@plt>:
 930:	ff 25 fa 16 20 00    	jmp    QWORD PTR [rip+0x2016fa]        # 202030 <__stack_chk_fail@GLIBC_2.4>
 936:	68 03 00 00 00       	push   0x3
 93b:	e9 b0 ff ff ff       	jmp    8f0 <.plt>

0000000000000940 <printf@plt>:
 940:	ff 25 f2 16 20 00    	jmp    QWORD PTR [rip+0x2016f2]        # 202038 <printf@GLIBC_2.2.5>
 946:	68 04 00 00 00       	push   0x4
 94b:	e9 a0 ff ff ff       	jmp    8f0 <.plt>

0000000000000950 <snprintf@plt>:
 950:	ff 25 ea 16 20 00    	jmp    QWORD PTR [rip+0x2016ea]        # 202040 <snprintf@GLIBC_2.2.5>
 956:	68 05 00 00 00       	push   0x5
 95b:	e9 90 ff ff ff       	jmp    8f0 <.plt>

0000000000000960 <dirname@plt>:
 960:	ff 25 e2 16 20 00    	jmp    QWORD PTR [rip+0x2016e2]        # 202048 <dirname@GLIBC_2.2.5>
 966:	68 06 00 00 00       	push   0x6
 96b:	e9 80 ff ff ff       	jmp    8f0 <.plt>

0000000000000970 <close@plt>:
 970:	ff 25 da 16 20 00    	jmp    QWORD PTR [rip+0x2016da]        # 202050 <close@GLIBC_2.2.5>
 976:	68 07 00 00 00       	push   0x7
 97b:	e9 70 ff ff ff       	jmp    8f0 <.plt>

0000000000000980 <read@plt>:
 980:	ff 25 d2 16 20 00    	jmp    QWORD PTR [rip+0x2016d2]        # 202058 <read@GLIBC_2.2.5>
 986:	68 08 00 00 00       	push   0x8
 98b:	e9 60 ff ff ff       	jmp    8f0 <.plt>

0000000000000990 <fgets@plt>:
 990:	ff 25 ca 16 20 00    	jmp    QWORD PTR [rip+0x2016ca]        # 202060 <fgets@GLIBC_2.2.5>
 996:	68 09 00 00 00       	push   0x9
 99b:	e9 50 ff ff ff       	jmp    8f0 <.plt>

00000000000009a0 <strtol@plt>:
 9a0:	ff 25 c2 16 20 00    	jmp    QWORD PTR [rip+0x2016c2]        # 202068 <strtol@GLIBC_2.2.5>
 9a6:	68 0a 00 00 00       	push   0xa
 9ab:	e9 40 ff ff ff       	jmp    8f0 <.plt>

00000000000009b0 <setvbuf@plt>:
 9b0:	ff 25 ba 16 20 00    	jmp    QWORD PTR [rip+0x2016ba]        # 202070 <setvbuf@GLIBC_2.2.5>
 9b6:	68 0b 00 00 00       	push   0xb
 9bb:	e9 30 ff ff ff       	jmp    8f0 <.plt>

00000000000009c0 <open@plt>:
 9c0:	ff 25 b2 16 20 00    	jmp    QWORD PTR [rip+0x2016b2]        # 202078 <open@GLIBC_2.2.5>
 9c6:	68 0c 00 00 00       	push   0xc
 9cb:	e9 20 ff ff ff       	jmp    8f0 <.plt>

00000000000009d0 <exit@plt>:
 9d0:	ff 25 aa 16 20 00    	jmp    QWORD PTR [rip+0x2016aa]        # 202080 <exit@GLIBC_2.2.5>
 9d6:	68 0d 00 00 00       	push   0xd
 9db:	e9 10 ff ff ff       	jmp    8f0 <.plt>

Disassembly of section .plt.got:

00000000000009e0 <puts@plt>:
 9e0:	ff 25 f2 15 20 00    	jmp    QWORD PTR [rip+0x2015f2]        # 201fd8 <puts@GLIBC_2.2.5>
 9e6:	66 90                	xchg   ax,ax

00000000000009e8 <__cxa_finalize@plt>:
 9e8:	ff 25 0a 16 20 00    	jmp    QWORD PTR [rip+0x20160a]        # 201ff8 <__cxa_finalize@GLIBC_2.2.5>
 9ee:	66 90                	xchg   ax,ax

Disassembly of section .text:

00000000000009f0 <_start>:
 9f0:	31 ed                	xor    ebp,ebp
 9f2:	49 89 d1             	mov    r9,rdx
 9f5:	5e                   	pop    rsi
 9f6:	48 89 e2             	mov    rdx,rsp
 9f9:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
 9fd:	50                   	push   rax
 9fe:	54                   	push   rsp
 9ff:	4c 8d 05 fa 03 00 00 	lea    r8,[rip+0x3fa]        # e00 <__libc_csu_fini>
 a06:	48 8d 0d 83 03 00 00 	lea    rcx,[rip+0x383]        # d90 <__libc_csu_init>
 a0d:	48 8d 3d 6a 02 00 00 	lea    rdi,[rip+0x26a]        # c7e <main>
 a14:	ff 15 c6 15 20 00    	call   QWORD PTR [rip+0x2015c6]        # 201fe0 <__libc_start_main@GLIBC_2.2.5>
 a1a:	f4                   	hlt    
 a1b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000000a20 <deregister_tm_clones>:
 a20:	48 8d 3d 71 16 20 00 	lea    rdi,[rip+0x201671]        # 202098 <__TMC_END__>
 a27:	55                   	push   rbp
 a28:	48 8d 05 69 16 20 00 	lea    rax,[rip+0x201669]        # 202098 <__TMC_END__>
 a2f:	48 39 f8             	cmp    rax,rdi
 a32:	48 89 e5             	mov    rbp,rsp
 a35:	74 19                	je     a50 <deregister_tm_clones+0x30>
 a37:	48 8b 05 92 15 20 00 	mov    rax,QWORD PTR [rip+0x201592]        # 201fd0 <_ITM_deregisterTMCloneTable>
 a3e:	48 85 c0             	test   rax,rax
 a41:	74 0d                	je     a50 <deregister_tm_clones+0x30>
 a43:	5d                   	pop    rbp
 a44:	ff e0                	jmp    rax
 a46:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
 a4d:	00 00 00 
 a50:	5d                   	pop    rbp
 a51:	c3                   	ret    
 a52:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
 a56:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
 a5d:	00 00 00 

0000000000000a60 <register_tm_clones>:
 a60:	48 8d 3d 31 16 20 00 	lea    rdi,[rip+0x201631]        # 202098 <__TMC_END__>
 a67:	48 8d 35 2a 16 20 00 	lea    rsi,[rip+0x20162a]        # 202098 <__TMC_END__>
 a6e:	55                   	push   rbp
 a6f:	48 29 fe             	sub    rsi,rdi
 a72:	48 89 e5             	mov    rbp,rsp
 a75:	48 c1 fe 03          	sar    rsi,0x3
 a79:	48 89 f0             	mov    rax,rsi
 a7c:	48 c1 e8 3f          	shr    rax,0x3f
 a80:	48 01 c6             	add    rsi,rax
 a83:	48 d1 fe             	sar    rsi,1
 a86:	74 18                	je     aa0 <register_tm_clones+0x40>
 a88:	48 8b 05 61 15 20 00 	mov    rax,QWORD PTR [rip+0x201561]        # 201ff0 <_ITM_registerTMCloneTable>
 a8f:	48 85 c0             	test   rax,rax
 a92:	74 0c                	je     aa0 <register_tm_clones+0x40>
 a94:	5d                   	pop    rbp
 a95:	ff e0                	jmp    rax
 a97:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
 a9e:	00 00 
 aa0:	5d                   	pop    rbp
 aa1:	c3                   	ret    
 aa2:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
 aa6:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
 aad:	00 00 00 

0000000000000ab0 <__do_global_dtors_aux>:
 ab0:	80 3d 11 16 20 00 00 	cmp    BYTE PTR [rip+0x201611],0x0        # 2020c8 <completed.7698>
 ab7:	75 2f                	jne    ae8 <__do_global_dtors_aux+0x38>
 ab9:	48 83 3d 37 15 20 00 	cmp    QWORD PTR [rip+0x201537],0x0        # 201ff8 <__cxa_finalize@GLIBC_2.2.5>
 ac0:	00 
 ac1:	55                   	push   rbp
 ac2:	48 89 e5             	mov    rbp,rsp
 ac5:	74 0c                	je     ad3 <__do_global_dtors_aux+0x23>
 ac7:	48 8b 3d c2 15 20 00 	mov    rdi,QWORD PTR [rip+0x2015c2]        # 202090 <__dso_handle>
 ace:	e8 15 ff ff ff       	call   9e8 <__cxa_finalize@plt>
 ad3:	e8 48 ff ff ff       	call   a20 <deregister_tm_clones>
 ad8:	c6 05 e9 15 20 00 01 	mov    BYTE PTR [rip+0x2015e9],0x1        # 2020c8 <completed.7698>
 adf:	5d                   	pop    rbp
 ae0:	c3                   	ret    
 ae1:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
 ae8:	f3 c3                	repz ret 
 aea:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

0000000000000af0 <frame_dummy>:
 af0:	55                   	push   rbp
 af1:	48 89 e5             	mov    rbp,rsp
 af4:	5d                   	pop    rbp
 af5:	e9 66 ff ff ff       	jmp    a60 <register_tm_clones>

0000000000000afa <unbuffered>:
 afa:	55                   	push   rbp
 afb:	48 89 e5             	mov    rbp,rsp
 afe:	48 8b 05 ab 15 20 00 	mov    rax,QWORD PTR [rip+0x2015ab]        # 2020b0 <stdin@@GLIBC_2.2.5>
 b05:	b9 00 00 00 00       	mov    ecx,0x0
 b0a:	ba 02 00 00 00       	mov    edx,0x2
 b0f:	be 00 00 00 00       	mov    esi,0x0
 b14:	48 89 c7             	mov    rdi,rax
 b17:	e8 94 fe ff ff       	call   9b0 <setvbuf@plt>
 b1c:	48 8b 05 9d 15 20 00 	mov    rax,QWORD PTR [rip+0x20159d]        # 2020c0 <stderr@@GLIBC_2.2.5>
 b23:	b9 00 00 00 00       	mov    ecx,0x0
 b28:	ba 02 00 00 00       	mov    edx,0x2
 b2d:	be 00 00 00 00       	mov    esi,0x0
 b32:	48 89 c7             	mov    rdi,rax
 b35:	e8 76 fe ff ff       	call   9b0 <setvbuf@plt>
 b3a:	48 8b 05 5f 15 20 00 	mov    rax,QWORD PTR [rip+0x20155f]        # 2020a0 <stdout@@GLIBC_2.2.5>
 b41:	b9 00 00 00 00       	mov    ecx,0x0
 b46:	ba 02 00 00 00       	mov    edx,0x2
 b4b:	be 00 00 00 00       	mov    esi,0x0
 b50:	48 89 c7             	mov    rdi,rax
 b53:	e8 58 fe ff ff       	call   9b0 <setvbuf@plt>
 b58:	90                   	nop
 b59:	5d                   	pop    rbp
 b5a:	c3                   	ret    

0000000000000c5a <magic>:
 c5a:	55                   	push   rbp
 c5b:	48 89 e5             	mov    rbp,rsp
 c5e:	48 8d 3d c6 01 00 00 	lea    rdi,[rip+0x1c6]        # e2b <_IO_stdin_used+0x1b>
 c65:	e8 76 fd ff ff       	call   9e0 <puts@plt>
 c6a:	b8 00 00 00 00       	mov    eax,0x0
 c6f:	e8 e7 fe ff ff       	call   b5b <showflag>
 c74:	bf 00 00 00 00       	mov    edi,0x0
 c79:	e8 82 fc ff ff       	call   900 <_exit@plt>

0000000000000c7e <main>:
 c7e:	55                   	push   rbp
 c7f:	48 89 e5             	mov    rbp,rsp
 c82:	48 83 ec 60          	sub    rsp,0x60
 c86:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
 c8d:	00 00 
 c8f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
 c93:	31 c0                	xor    eax,eax
 c95:	b8 00 00 00 00       	mov    eax,0x0
 c9a:	e8 5b fe ff ff       	call   afa <unbuffered>
 c9f:	48 8d 3d 8c 01 00 00 	lea    rdi,[rip+0x18c]        # e32 <_IO_stdin_used+0x22>
 ca6:	e8 35 fd ff ff       	call   9e0 <puts@plt>
 cab:	48 8d 35 cc ff ff ff 	lea    rsi,[rip+0xffffffffffffffcc]        # c7e <main>
 cb2:	48 8d 3d 82 01 00 00 	lea    rdi,[rip+0x182]        # e3b <_IO_stdin_used+0x2b>
 cb9:	b8 00 00 00 00       	mov    eax,0x0
 cbe:	e8 7d fc ff ff       	call   940 <printf@plt>
 cc3:	48 8b 05 0e 13 20 00 	mov    rax,QWORD PTR [rip+0x20130e]        # 201fd8 <puts@GLIBC_2.2.5>
 cca:	48 89 c6             	mov    rsi,rax
 ccd:	48 8d 3d 74 01 00 00 	lea    rdi,[rip+0x174]        # e48 <_IO_stdin_used+0x38>
 cd4:	b8 00 00 00 00       	mov    eax,0x0
 cd9:	e8 62 fc ff ff       	call   940 <printf@plt>
 cde:	48 8d 3d 70 01 00 00 	lea    rdi,[rip+0x170]        # e55 <_IO_stdin_used+0x45>
 ce5:	e8 f6 fc ff ff       	call   9e0 <puts@plt>
 cea:	48 8d 3d 65 01 00 00 	lea    rdi,[rip+0x165]        # e56 <_IO_stdin_used+0x46>
 cf1:	e8 ea fc ff ff       	call   9e0 <puts@plt>
 cf6:	48 8b 15 b3 13 20 00 	mov    rdx,QWORD PTR [rip+0x2013b3]        # 2020b0 <stdin@@GLIBC_2.2.5>
 cfd:	48 8d 45 b0          	lea    rax,[rbp-0x50]
 d01:	be 40 00 00 00       	mov    esi,0x40
 d06:	48 89 c7             	mov    rdi,rax
 d09:	e8 82 fc ff ff       	call   990 <fgets@plt>
 d0e:	48 85 c0             	test   rax,rax
 d11:	74 6a                	je     d7d <main+0xff>
 d13:	48 8d 45 b0          	lea    rax,[rbp-0x50]
 d17:	ba 00 00 00 00       	mov    edx,0x0
 d1c:	be 00 00 00 00       	mov    esi,0x0
 d21:	48 89 c7             	mov    rdi,rax
 d24:	e8 77 fc ff ff       	call   9a0 <strtol@plt>
 d29:	48 89 45 a0          	mov    QWORD PTR [rbp-0x60],rax
 d2d:	48 8d 3d 3f 01 00 00 	lea    rdi,[rip+0x13f]        # e73 <_IO_stdin_used+0x63>
 d34:	e8 a7 fc ff ff       	call   9e0 <puts@plt>
 d39:	48 8b 15 70 13 20 00 	mov    rdx,QWORD PTR [rip+0x201370]        # 2020b0 <stdin@@GLIBC_2.2.5>
 d40:	48 8d 45 b0          	lea    rax,[rbp-0x50]
 d44:	be 40 00 00 00       	mov    esi,0x40
 d49:	48 89 c7             	mov    rdi,rax
 d4c:	e8 3f fc ff ff       	call   990 <fgets@plt>
 d51:	48 85 c0             	test   rax,rax
 d54:	74 2a                	je     d80 <main+0x102>
 d56:	48 8d 45 b0          	lea    rax,[rbp-0x50]
 d5a:	ba 00 00 00 00       	mov    edx,0x0
 d5f:	be 00 00 00 00       	mov    esi,0x0
 d64:	48 89 c7             	mov    rdi,rax
 d67:	e8 34 fc ff ff       	call   9a0 <strtol@plt>
 d6c:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
 d70:	48 8b 45 a0          	mov    rax,QWORD PTR [rbp-0x60]
 d74:	48 8b 55 a8          	mov    rdx,QWORD PTR [rbp-0x58]
 d78:	48 89 10             	mov    QWORD PTR [rax],rdx
 d7b:	eb 04                	jmp    d81 <main+0x103>
 d7d:	90                   	nop
 d7e:	eb 01                	jmp    d81 <main+0x103>
 d80:	90                   	nop
 d81:	bf 00 00 00 00       	mov    edi,0x0
 d86:	e8 45 fc ff ff       	call   9d0 <exit@plt>
 d8b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000000d90 <__libc_csu_init>:
 d90:	41 57                	push   r15
 d92:	41 56                	push   r14
 d94:	49 89 d7             	mov    r15,rdx
 d97:	41 55                	push   r13
 d99:	41 54                	push   r12
 d9b:	4c 8d 25 3e 10 20 00 	lea    r12,[rip+0x20103e]        # 201de0 <__frame_dummy_init_array_entry>
 da2:	55                   	push   rbp
 da3:	48 8d 2d 3e 10 20 00 	lea    rbp,[rip+0x20103e]        # 201de8 <__init_array_end>
 daa:	53                   	push   rbx
 dab:	41 89 fd             	mov    r13d,edi
 dae:	49 89 f6             	mov    r14,rsi
 db1:	4c 29 e5             	sub    rbp,r12
 db4:	48 83 ec 08          	sub    rsp,0x8
 db8:	48 c1 fd 03          	sar    rbp,0x3
 dbc:	e8 17 fb ff ff       	call   8d8 <_init>
 dc1:	48 85 ed             	test   rbp,rbp
 dc4:	74 20                	je     de6 <__libc_csu_init+0x56>
 dc6:	31 db                	xor    ebx,ebx
 dc8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
 dcf:	00 
 dd0:	4c 89 fa             	mov    rdx,r15
 dd3:	4c 89 f6             	mov    rsi,r14
 dd6:	44 89 ef             	mov    edi,r13d
 dd9:	41 ff 14 dc          	call   QWORD PTR [r12+rbx*8]
 ddd:	48 83 c3 01          	add    rbx,0x1
 de1:	48 39 dd             	cmp    rbp,rbx
 de4:	75 ea                	jne    dd0 <__libc_csu_init+0x40>
 de6:	48 83 c4 08          	add    rsp,0x8
 dea:	5b                   	pop    rbx
 deb:	5d                   	pop    rbp
 dec:	41 5c                	pop    r12
 dee:	41 5d                	pop    r13
 df0:	41 5e                	pop    r14
 df2:	41 5f                	pop    r15
 df4:	c3                   	ret    
 df5:	90                   	nop
 df6:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
 dfd:	00 00 00 

0000000000000e00 <__libc_csu_fini>:
 e00:	f3 c3                	repz ret 

Disassembly of section .fini:

0000000000000e04 <_fini>:
 e04:	48 83 ec 08          	sub    rsp,0x8
 e08:	48 83 c4 08          	add    rsp,0x8
 e0c:	c3                   	ret    

Disassembly of section .rodata:

0000000000000e10 <_IO_stdin_used>:
 e10:	01 00                	add    DWORD PTR [rax],eax
 e12:	02 00                	add    al,BYTE PTR [rax]
 e14:	2f                   	(bad)  
 e15:	70 72                	jo     e89 <_IO_stdin_used+0x79>
 e17:	6f                   	outs   dx,DWORD PTR ds:[rsi]
 e18:	63 2f                	movsxd ebp,DWORD PTR [rdi]
 e1a:	73 65                	jae    e81 <_IO_stdin_used+0x71>
 e1c:	6c                   	ins    BYTE PTR es:[rdi],dx
 e1d:	66 2f                	data16 (bad) 
 e1f:	65 78 65             	gs js  e87 <_IO_stdin_used+0x77>
 e22:	00 25 73 2f 46 4c    	add    BYTE PTR [rip+0x4c462f73],ah        # 4c463d9b <_end+0x4c261ccb>
 e28:	41                   	rex.B
 e29:	47 00 42 69          	rex.RXB add BYTE PTR [r10+0x69],r8b
 e2d:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 e2e:	67 6f                	outs   dx,DWORD PTR ds:[esi]
 e30:	21 00                	and    DWORD PTR [rax],eax
 e32:	57                   	push   rdi
 e33:	65 6c                	gs ins BYTE PTR es:[rdi],dx
 e35:	63 6f 6d             	movsxd ebp,DWORD PTR [rdi+0x6d]
 e38:	65 21 00             	and    DWORD PTR gs:[rax],eax
 e3b:	2d 20 6d 61 69       	sub    eax,0x69616d20
 e40:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 e41:	20 40 20             	and    BYTE PTR [rax+0x20],al
 e44:	25 70 0a 00 2d       	and    eax,0x2d000a70
 e49:	20 70 75             	and    BYTE PTR [rax+0x75],dh
 e4c:	74 73                	je     ec1 <__GNU_EH_FRAME_HDR+0x31>
 e4e:	20 40 20             	and    BYTE PTR [rax+0x20],al
 e51:	25 70 0a 00 00       	and    eax,0xa70
 e56:	57                   	push   rdi
 e57:	68 65 72 65 20       	push   0x20657265
 e5c:	64 6f                	outs   dx,DWORD PTR fs:[rsi]
 e5e:	20 79 6f             	and    BYTE PTR [rcx+0x6f],bh
 e61:	75 20                	jne    e83 <_IO_stdin_used+0x73>
 e63:	77 61                	ja     ec6 <__GNU_EH_FRAME_HDR+0x36>
 e65:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 e66:	74 20                	je     e88 <_IO_stdin_used+0x78>
 e68:	74 6f                	je     ed9 <__GNU_EH_FRAME_HDR+0x49>
 e6a:	20 77 72             	and    BYTE PTR [rdi+0x72],dh
 e6d:	69 74 65 3f 20 00 57 	imul   esi,DWORD PTR [rbp+riz*2+0x3f],0x68570020
 e74:	68 
 e75:	61                   	(bad)  
 e76:	74 20                	je     e98 <__GNU_EH_FRAME_HDR+0x8>
 e78:	64 6f                	outs   dx,DWORD PTR fs:[rsi]
 e7a:	20 79 6f             	and    BYTE PTR [rcx+0x6f],bh
 e7d:	75 20                	jne    e9f <__GNU_EH_FRAME_HDR+0xf>
 e7f:	77 61                	ja     ee2 <__GNU_EH_FRAME_HDR+0x52>
 e81:	6e                   	outs   dx,BYTE PTR ds:[rsi]
 e82:	74 20                	je     ea4 <__GNU_EH_FRAME_HDR+0x14>
 e84:	74 6f                	je     ef5 <__GNU_EH_FRAME_HDR+0x65>
 e86:	20 77 72             	and    BYTE PTR [rdi+0x72],dh
 e89:	69                   	.byte 0x69
 e8a:	74 65                	je     ef1 <__GNU_EH_FRAME_HDR+0x61>
 e8c:	3f                   	(bad)  
 e8d:	20 00                	and    BYTE PTR [rax],al

Disassembly of section .eh_frame_hdr:

0000000000000e90 <__GNU_EH_FRAME_HDR>:
 e90:	01 1b                	add    DWORD PTR [rbx],ebx
 e92:	03 3b                	add    edi,DWORD PTR [rbx]
 e94:	54                   	push   rsp
 e95:	00 00                	add    BYTE PTR [rax],al
 e97:	00 09                	add    BYTE PTR [rcx],cl
 e99:	00 00                	add    BYTE PTR [rax],al
 e9b:	00 60 fa             	add    BYTE PTR [rax-0x6],ah
 e9e:	ff                   	(bad)  
 e9f:	ff a0 00 00 00 50    	jmp    QWORD PTR [rax+0x50000000]
 ea5:	fb                   	sti    
 ea6:	ff                   	(bad)  
 ea7:	ff c8                	dec    eax
 ea9:	00 00                	add    BYTE PTR [rax],al
 eab:	00 60 fb             	add    BYTE PTR [rax-0x5],ah
 eae:	ff                   	(bad)  
 eaf:	ff 70 00             	push   QWORD PTR [rax+0x0]
 eb2:	00 00                	add    BYTE PTR [rax],al
 eb4:	6a fc                	push   0xfffffffffffffffc
 eb6:	ff                   	(bad)  
 eb7:	ff e0                	jmp    rax
 eb9:	00 00                	add    BYTE PTR [rax],al
 ebb:	00 cb                	add    bl,cl
 ebd:	fc                   	cld    
 ebe:	ff                   	(bad)  
 ebf:	ff 00                	inc    DWORD PTR [rax]
 ec1:	01 00                	add    DWORD PTR [rax],eax
 ec3:	00 ca                	add    dl,cl
 ec5:	fd                   	std    
 ec6:	ff                   	(bad)  
 ec7:	ff 20                	jmp    QWORD PTR [rax]
 ec9:	01 00                	add    DWORD PTR [rax],eax
 ecb:	00 ee                	add    dh,ch
 ecd:	fd                   	std    
 ece:	ff                   	(bad)  
 ecf:	ff                   	(bad)  
 ed0:	3c 01                	cmp    al,0x1
 ed2:	00 00                	add    BYTE PTR [rax],al
 ed4:	00 ff                	add    bh,bh
 ed6:	ff                   	(bad)  
 ed7:	ff 58 01             	call   FWORD PTR [rax+0x1]
 eda:	00 00                	add    BYTE PTR [rax],al
 edc:	70 ff                	jo     edd <__GNU_EH_FRAME_HDR+0x4d>
 ede:	ff                   	(bad)  
 edf:	ff                   	.byte 0xff
 ee0:	a0                   	.byte 0xa0
 ee1:	01 00                	add    DWORD PTR [rax],eax
	...

Disassembly of section .eh_frame:

0000000000000ee8 <__FRAME_END__-0x15c>:
     ee8:	14 00                	adc    al,0x0
     eea:	00 00                	add    BYTE PTR [rax],al
     eec:	00 00                	add    BYTE PTR [rax],al
     eee:	00 00                	add    BYTE PTR [rax],al
     ef0:	01 7a 52             	add    DWORD PTR [rdx+0x52],edi
     ef3:	00 01                	add    BYTE PTR [rcx],al
     ef5:	78 10                	js     f07 <__GNU_EH_FRAME_HDR+0x77>
     ef7:	01 1b                	add    DWORD PTR [rbx],ebx
     ef9:	0c 07                	or     al,0x7
     efb:	08 90 01 07 10 14    	or     BYTE PTR [rax+0x14100701],dl
     f01:	00 00                	add    BYTE PTR [rax],al
     f03:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
     f06:	00 00                	add    BYTE PTR [rax],al
     f08:	e8 fa ff ff 2b       	call   2c000f07 <_end+0x2bdfee37>
	...
     f15:	00 00                	add    BYTE PTR [rax],al
     f17:	00 14 00             	add    BYTE PTR [rax+rax*1],dl
     f1a:	00 00                	add    BYTE PTR [rax],al
     f1c:	00 00                	add    BYTE PTR [rax],al
     f1e:	00 00                	add    BYTE PTR [rax],al
     f20:	01 7a 52             	add    DWORD PTR [rdx+0x52],edi
     f23:	00 01                	add    BYTE PTR [rcx],al
     f25:	78 10                	js     f37 <__GNU_EH_FRAME_HDR+0xa7>
     f27:	01 1b                	add    DWORD PTR [rbx],ebx
     f29:	0c 07                	or     al,0x7
     f2b:	08 90 01 00 00 24    	or     BYTE PTR [rax+0x24000001],dl
     f31:	00 00                	add    BYTE PTR [rax],al
     f33:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
     f36:	00 00                	add    BYTE PTR [rax],al
     f38:	b8 f9 ff ff f0       	mov    eax,0xf0fffff9
     f3d:	00 00                	add    BYTE PTR [rax],al
     f3f:	00 00                	add    BYTE PTR [rax],al
     f41:	0e                   	(bad)  
     f42:	10 46 0e             	adc    BYTE PTR [rsi+0xe],al
     f45:	18 4a 0f             	sbb    BYTE PTR [rdx+0xf],cl
     f48:	0b 77 08             	or     esi,DWORD PTR [rdi+0x8]
     f4b:	80 00 3f             	add    BYTE PTR [rax],0x3f
     f4e:	1a 3b                	sbb    bh,BYTE PTR [rbx]
     f50:	2a 33                	sub    dh,BYTE PTR [rbx]
     f52:	24 22                	and    al,0x22
     f54:	00 00                	add    BYTE PTR [rax],al
     f56:	00 00                	add    BYTE PTR [rax],al
     f58:	14 00                	adc    al,0x0
     f5a:	00 00                	add    BYTE PTR [rax],al
     f5c:	44 00 00             	add    BYTE PTR [rax],r8b
     f5f:	00 80 fa ff ff 10    	add    BYTE PTR [rax+0x10fffffa],al
	...
     f6d:	00 00                	add    BYTE PTR [rax],al
     f6f:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
     f72:	00 00                	add    BYTE PTR [rax],al
     f74:	5c                   	pop    rsp
     f75:	00 00                	add    BYTE PTR [rax],al
     f77:	00 82 fb ff ff 61    	add    BYTE PTR [rdx+0x61fffffb],al
     f7d:	00 00                	add    BYTE PTR [rax],al
     f7f:	00 00                	add    BYTE PTR [rax],al
     f81:	41 0e                	rex.B (bad) 
     f83:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
     f89:	02 5c 0c 07          	add    bl,BYTE PTR [rsp+rcx*1+0x7]
     f8d:	08 00                	or     BYTE PTR [rax],al
     f8f:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
     f92:	00 00                	add    BYTE PTR [rax],al
     f94:	7c 00                	jl     f96 <__GNU_EH_FRAME_HDR+0x106>
     f96:	00 00                	add    BYTE PTR [rax],al
     f98:	c3                   	ret    
     f99:	fb                   	sti    
     f9a:	ff                   	(bad)  
     f9b:	ff                   	(bad)  
     f9c:	ff 00                	inc    DWORD PTR [rax]
     f9e:	00 00                	add    BYTE PTR [rax],al
     fa0:	00 41 0e             	add    BYTE PTR [rcx+0xe],al
     fa3:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
     fa9:	02 fa                	add    bh,dl
     fab:	0c 07                	or     al,0x7
     fad:	08 00                	or     BYTE PTR [rax],al
     faf:	00 18                	add    BYTE PTR [rax],bl
     fb1:	00 00                	add    BYTE PTR [rax],al
     fb3:	00 9c 00 00 00 a2 fc 	add    BYTE PTR [rax+rax*1-0x35e0000],bl
     fba:	ff                   	(bad)  
     fbb:	ff 24 00             	jmp    QWORD PTR [rax+rax*1]
     fbe:	00 00                	add    BYTE PTR [rax],al
     fc0:	00 41 0e             	add    BYTE PTR [rcx+0xe],al
     fc3:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
     fc9:	00 00                	add    BYTE PTR [rax],al
     fcb:	00 18                	add    BYTE PTR [rax],bl
     fcd:	00 00                	add    BYTE PTR [rax],al
     fcf:	00 b8 00 00 00 aa    	add    BYTE PTR [rax-0x56000000],bh
     fd5:	fc                   	cld    
     fd6:	ff                   	(bad)  
     fd7:	ff 0d 01 00 00 00    	dec    DWORD PTR [rip+0x1]        # fde <__GNU_EH_FRAME_HDR+0x14e>
     fdd:	41 0e                	rex.B (bad) 
     fdf:	10 86 02 43 0d 06    	adc    BYTE PTR [rsi+0x60d4302],al
     fe5:	00 00                	add    BYTE PTR [rax],al
     fe7:	00 44 00 00          	add    BYTE PTR [rax+rax*1+0x0],al
     feb:	00 d4                	add    ah,dl
     fed:	00 00                	add    BYTE PTR [rax],al
     fef:	00 a0 fd ff ff 65    	add    BYTE PTR [rax+0x65fffffd],ah
     ff5:	00 00                	add    BYTE PTR [rax],al
     ff7:	00 00                	add    BYTE PTR [rax],al
     ff9:	42 0e                	rex.X (bad) 
     ffb:	10 8f 02 42 0e 18    	adc    BYTE PTR [rdi+0x180e4202],cl
    1001:	8e 03                	mov    es,WORD PTR [rbx]
    1003:	45 0e                	rex.RB (bad) 
    1005:	20 8d 04 42 0e 28    	and    BYTE PTR [rbp+0x280e4204],cl
    100b:	8c 05 48 0e 30 86    	mov    WORD PTR [rip+0xffffffff86300e48],es        # ffffffff86301e59 <_end+0xffffffff860ffd89>
    1011:	06                   	(bad)  
    1012:	48 0e                	rex.W (bad) 
    1014:	38 83 07 4d 0e 40    	cmp    BYTE PTR [rbx+0x400e4d07],al
    101a:	72 0e                	jb     102a <__GNU_EH_FRAME_HDR+0x19a>
    101c:	38 41 0e             	cmp    BYTE PTR [rcx+0xe],al
    101f:	30 41 0e             	xor    BYTE PTR [rcx+0xe],al
    1022:	28 42 0e             	sub    BYTE PTR [rdx+0xe],al
    1025:	20 42 0e             	and    BYTE PTR [rdx+0xe],al
    1028:	18 42 0e             	sbb    BYTE PTR [rdx+0xe],al
    102b:	10 42 0e             	adc    BYTE PTR [rdx+0xe],al
    102e:	08 00                	or     BYTE PTR [rax],al
    1030:	10 00                	adc    BYTE PTR [rax],al
    1032:	00 00                	add    BYTE PTR [rax],al
    1034:	1c 01                	sbb    al,0x1
    1036:	00 00                	add    BYTE PTR [rax],al
    1038:	c8 fd ff ff          	enter  0xfffd,0xff
    103c:	02 00                	add    al,BYTE PTR [rax]
    103e:	00 00                	add    BYTE PTR [rax],al
    1040:	00 00                	add    BYTE PTR [rax],al
	...

0000000000001044 <__FRAME_END__>:
    1044:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .init_array:

0000000000201de0 <__frame_dummy_init_array_entry>:
  201de0:	f0 0a 00             	lock or al,BYTE PTR [rax]
  201de3:	00 00                	add    BYTE PTR [rax],al
  201de5:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .fini_array:

0000000000201de8 <__do_global_dtors_aux_fini_array_entry>:
  201de8:	b0 0a                	mov    al,0xa
  201dea:	00 00                	add    BYTE PTR [rax],al
  201dec:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .dynamic:

0000000000201df0 <_DYNAMIC>:
  201df0:	01 00                	add    DWORD PTR [rax],eax
  201df2:	00 00                	add    BYTE PTR [rax],al
  201df4:	00 00                	add    BYTE PTR [rax],al
  201df6:	00 00                	add    BYTE PTR [rax],al
  201df8:	01 00                	add    DWORD PTR [rax],eax
  201dfa:	00 00                	add    BYTE PTR [rax],al
  201dfc:	00 00                	add    BYTE PTR [rax],al
  201dfe:	00 00                	add    BYTE PTR [rax],al
  201e00:	0c 00                	or     al,0x0
  201e02:	00 00                	add    BYTE PTR [rax],al
  201e04:	00 00                	add    BYTE PTR [rax],al
  201e06:	00 00                	add    BYTE PTR [rax],al
  201e08:	d8 08                	fmul   DWORD PTR [rax]
  201e0a:	00 00                	add    BYTE PTR [rax],al
  201e0c:	00 00                	add    BYTE PTR [rax],al
  201e0e:	00 00                	add    BYTE PTR [rax],al
  201e10:	0d 00 00 00 00       	or     eax,0x0
  201e15:	00 00                	add    BYTE PTR [rax],al
  201e17:	00 04 0e             	add    BYTE PTR [rsi+rcx*1],al
  201e1a:	00 00                	add    BYTE PTR [rax],al
  201e1c:	00 00                	add    BYTE PTR [rax],al
  201e1e:	00 00                	add    BYTE PTR [rax],al
  201e20:	19 00                	sbb    DWORD PTR [rax],eax
  201e22:	00 00                	add    BYTE PTR [rax],al
  201e24:	00 00                	add    BYTE PTR [rax],al
  201e26:	00 00                	add    BYTE PTR [rax],al
  201e28:	e0 1d                	loopne 201e47 <_DYNAMIC+0x57>
  201e2a:	20 00                	and    BYTE PTR [rax],al
  201e2c:	00 00                	add    BYTE PTR [rax],al
  201e2e:	00 00                	add    BYTE PTR [rax],al
  201e30:	1b 00                	sbb    eax,DWORD PTR [rax]
  201e32:	00 00                	add    BYTE PTR [rax],al
  201e34:	00 00                	add    BYTE PTR [rax],al
  201e36:	00 00                	add    BYTE PTR [rax],al
  201e38:	08 00                	or     BYTE PTR [rax],al
  201e3a:	00 00                	add    BYTE PTR [rax],al
  201e3c:	00 00                	add    BYTE PTR [rax],al
  201e3e:	00 00                	add    BYTE PTR [rax],al
  201e40:	1a 00                	sbb    al,BYTE PTR [rax]
  201e42:	00 00                	add    BYTE PTR [rax],al
  201e44:	00 00                	add    BYTE PTR [rax],al
  201e46:	00 00                	add    BYTE PTR [rax],al
  201e48:	e8 1d 20 00 00       	call   203e6a <_end+0x1d9a>
  201e4d:	00 00                	add    BYTE PTR [rax],al
  201e4f:	00 1c 00             	add    BYTE PTR [rax+rax*1],bl
  201e52:	00 00                	add    BYTE PTR [rax],al
  201e54:	00 00                	add    BYTE PTR [rax],al
  201e56:	00 00                	add    BYTE PTR [rax],al
  201e58:	08 00                	or     BYTE PTR [rax],al
  201e5a:	00 00                	add    BYTE PTR [rax],al
  201e5c:	00 00                	add    BYTE PTR [rax],al
  201e5e:	00 00                	add    BYTE PTR [rax],al
  201e60:	f5                   	cmc    
  201e61:	fe                   	(bad)  
  201e62:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  201e65:	00 00                	add    BYTE PTR [rax],al
  201e67:	00 98 02 00 00 00    	add    BYTE PTR [rax+0x2],bl
  201e6d:	00 00                	add    BYTE PTR [rax],al
  201e6f:	00 05 00 00 00 00    	add    BYTE PTR [rip+0x0],al        # 201e75 <_DYNAMIC+0x85>
  201e75:	00 00                	add    BYTE PTR [rax],al
  201e77:	00 08                	add    BYTE PTR [rax],cl
  201e79:	05 00 00 00 00       	add    eax,0x0
  201e7e:	00 00                	add    BYTE PTR [rax],al
  201e80:	06                   	(bad)  
  201e81:	00 00                	add    BYTE PTR [rax],al
  201e83:	00 00                	add    BYTE PTR [rax],al
  201e85:	00 00                	add    BYTE PTR [rax],al
  201e87:	00 c8                	add    al,cl
  201e89:	02 00                	add    al,BYTE PTR [rax]
  201e8b:	00 00                	add    BYTE PTR [rax],al
  201e8d:	00 00                	add    BYTE PTR [rax],al
  201e8f:	00 0a                	add    BYTE PTR [rdx],cl
  201e91:	00 00                	add    BYTE PTR [rax],al
  201e93:	00 00                	add    BYTE PTR [rax],al
  201e95:	00 00                	add    BYTE PTR [rax],al
  201e97:	00 fc                	add    ah,bh
  201e99:	00 00                	add    BYTE PTR [rax],al
  201e9b:	00 00                	add    BYTE PTR [rax],al
  201e9d:	00 00                	add    BYTE PTR [rax],al
  201e9f:	00 0b                	add    BYTE PTR [rbx],cl
  201ea1:	00 00                	add    BYTE PTR [rax],al
  201ea3:	00 00                	add    BYTE PTR [rax],al
  201ea5:	00 00                	add    BYTE PTR [rax],al
  201ea7:	00 18                	add    BYTE PTR [rax],bl
  201ea9:	00 00                	add    BYTE PTR [rax],al
  201eab:	00 00                	add    BYTE PTR [rax],al
  201ead:	00 00                	add    BYTE PTR [rax],al
  201eaf:	00 15 00 00 00 00    	add    BYTE PTR [rip+0x0],dl        # 201eb5 <_DYNAMIC+0xc5>
	...
  201ebd:	00 00                	add    BYTE PTR [rax],al
  201ebf:	00 03                	add    BYTE PTR [rbx],al
	...
  201ec9:	20 20                	and    BYTE PTR [rax],ah
  201ecb:	00 00                	add    BYTE PTR [rax],al
  201ecd:	00 00                	add    BYTE PTR [rax],al
  201ecf:	00 02                	add    BYTE PTR [rdx],al
  201ed1:	00 00                	add    BYTE PTR [rax],al
  201ed3:	00 00                	add    BYTE PTR [rax],al
  201ed5:	00 00                	add    BYTE PTR [rax],al
  201ed7:	00 50 01             	add    BYTE PTR [rax+0x1],dl
  201eda:	00 00                	add    BYTE PTR [rax],al
  201edc:	00 00                	add    BYTE PTR [rax],al
  201ede:	00 00                	add    BYTE PTR [rax],al
  201ee0:	14 00                	adc    al,0x0
  201ee2:	00 00                	add    BYTE PTR [rax],al
  201ee4:	00 00                	add    BYTE PTR [rax],al
  201ee6:	00 00                	add    BYTE PTR [rax],al
  201ee8:	07                   	(bad)  
  201ee9:	00 00                	add    BYTE PTR [rax],al
  201eeb:	00 00                	add    BYTE PTR [rax],al
  201eed:	00 00                	add    BYTE PTR [rax],al
  201eef:	00 17                	add    BYTE PTR [rdi],dl
  201ef1:	00 00                	add    BYTE PTR [rax],al
  201ef3:	00 00                	add    BYTE PTR [rax],al
  201ef5:	00 00                	add    BYTE PTR [rax],al
  201ef7:	00 88 07 00 00 00    	add    BYTE PTR [rax+0x7],cl
  201efd:	00 00                	add    BYTE PTR [rax],al
  201eff:	00 07                	add    BYTE PTR [rdi],al
  201f01:	00 00                	add    BYTE PTR [rax],al
  201f03:	00 00                	add    BYTE PTR [rax],al
  201f05:	00 00                	add    BYTE PTR [rax],al
  201f07:	00 68 06             	add    BYTE PTR [rax+0x6],ch
  201f0a:	00 00                	add    BYTE PTR [rax],al
  201f0c:	00 00                	add    BYTE PTR [rax],al
  201f0e:	00 00                	add    BYTE PTR [rax],al
  201f10:	08 00                	or     BYTE PTR [rax],al
  201f12:	00 00                	add    BYTE PTR [rax],al
  201f14:	00 00                	add    BYTE PTR [rax],al
  201f16:	00 00                	add    BYTE PTR [rax],al
  201f18:	20 01                	and    BYTE PTR [rcx],al
  201f1a:	00 00                	add    BYTE PTR [rax],al
  201f1c:	00 00                	add    BYTE PTR [rax],al
  201f1e:	00 00                	add    BYTE PTR [rax],al
  201f20:	09 00                	or     DWORD PTR [rax],eax
  201f22:	00 00                	add    BYTE PTR [rax],al
  201f24:	00 00                	add    BYTE PTR [rax],al
  201f26:	00 00                	add    BYTE PTR [rax],al
  201f28:	18 00                	sbb    BYTE PTR [rax],al
  201f2a:	00 00                	add    BYTE PTR [rax],al
  201f2c:	00 00                	add    BYTE PTR [rax],al
  201f2e:	00 00                	add    BYTE PTR [rax],al
  201f30:	fb                   	sti    
  201f31:	ff                   	(bad)  
  201f32:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  201f35:	00 00                	add    BYTE PTR [rax],al
  201f37:	00 00                	add    BYTE PTR [rax],al
  201f39:	00 00                	add    BYTE PTR [rax],al
  201f3b:	08 00                	or     BYTE PTR [rax],al
  201f3d:	00 00                	add    BYTE PTR [rax],al
  201f3f:	00 fe                	add    dh,bh
  201f41:	ff                   	(bad)  
  201f42:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  201f45:	00 00                	add    BYTE PTR [rax],al
  201f47:	00 38                	add    BYTE PTR [rax],bh
  201f49:	06                   	(bad)  
  201f4a:	00 00                	add    BYTE PTR [rax],al
  201f4c:	00 00                	add    BYTE PTR [rax],al
  201f4e:	00 00                	add    BYTE PTR [rax],al
  201f50:	ff                   	(bad)  
  201f51:	ff                   	(bad)  
  201f52:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  201f55:	00 00                	add    BYTE PTR [rax],al
  201f57:	00 01                	add    BYTE PTR [rcx],al
  201f59:	00 00                	add    BYTE PTR [rax],al
  201f5b:	00 00                	add    BYTE PTR [rax],al
  201f5d:	00 00                	add    BYTE PTR [rax],al
  201f5f:	00 f0                	add    al,dh
  201f61:	ff                   	(bad)  
  201f62:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  201f65:	00 00                	add    BYTE PTR [rax],al
  201f67:	00 04 06             	add    BYTE PTR [rsi+rax*1],al
  201f6a:	00 00                	add    BYTE PTR [rax],al
  201f6c:	00 00                	add    BYTE PTR [rax],al
  201f6e:	00 00                	add    BYTE PTR [rax],al
  201f70:	f9                   	stc    
  201f71:	ff                   	(bad)  
  201f72:	ff 6f 00             	jmp    FWORD PTR [rdi+0x0]
  201f75:	00 00                	add    BYTE PTR [rax],al
  201f77:	00 03                	add    BYTE PTR [rbx],al
	...

Disassembly of section .got:

0000000000201fd0 <.got>:
	...

Disassembly of section .got.plt:

0000000000202000 <_GLOBAL_OFFSET_TABLE_>:
  202000:	f0 1d 20 00 00 00    	lock sbb eax,0x20
	...
  202016:	00 00                	add    BYTE PTR [rax],al
  202018:	06                   	(bad)  
  202019:	09 00                	or     DWORD PTR [rax],eax
  20201b:	00 00                	add    BYTE PTR [rax],al
  20201d:	00 00                	add    BYTE PTR [rax],al
  20201f:	00 16                	add    BYTE PTR [rsi],dl
  202021:	09 00                	or     DWORD PTR [rax],eax
  202023:	00 00                	add    BYTE PTR [rax],al
  202025:	00 00                	add    BYTE PTR [rax],al
  202027:	00 26                	add    BYTE PTR [rsi],ah
  202029:	09 00                	or     DWORD PTR [rax],eax
  20202b:	00 00                	add    BYTE PTR [rax],al
  20202d:	00 00                	add    BYTE PTR [rax],al
  20202f:	00 36                	add    BYTE PTR [rsi],dh
  202031:	09 00                	or     DWORD PTR [rax],eax
  202033:	00 00                	add    BYTE PTR [rax],al
  202035:	00 00                	add    BYTE PTR [rax],al
  202037:	00 46 09             	add    BYTE PTR [rsi+0x9],al
  20203a:	00 00                	add    BYTE PTR [rax],al
  20203c:	00 00                	add    BYTE PTR [rax],al
  20203e:	00 00                	add    BYTE PTR [rax],al
  202040:	56                   	push   rsi
  202041:	09 00                	or     DWORD PTR [rax],eax
  202043:	00 00                	add    BYTE PTR [rax],al
  202045:	00 00                	add    BYTE PTR [rax],al
  202047:	00 66 09             	add    BYTE PTR [rsi+0x9],ah
  20204a:	00 00                	add    BYTE PTR [rax],al
  20204c:	00 00                	add    BYTE PTR [rax],al
  20204e:	00 00                	add    BYTE PTR [rax],al
  202050:	76 09                	jbe    20205b <_GLOBAL_OFFSET_TABLE_+0x5b>
  202052:	00 00                	add    BYTE PTR [rax],al
  202054:	00 00                	add    BYTE PTR [rax],al
  202056:	00 00                	add    BYTE PTR [rax],al
  202058:	86 09                	xchg   BYTE PTR [rcx],cl
  20205a:	00 00                	add    BYTE PTR [rax],al
  20205c:	00 00                	add    BYTE PTR [rax],al
  20205e:	00 00                	add    BYTE PTR [rax],al
  202060:	96                   	xchg   esi,eax
  202061:	09 00                	or     DWORD PTR [rax],eax
  202063:	00 00                	add    BYTE PTR [rax],al
  202065:	00 00                	add    BYTE PTR [rax],al
  202067:	00 a6 09 00 00 00    	add    BYTE PTR [rsi+0x9],ah
  20206d:	00 00                	add    BYTE PTR [rax],al
  20206f:	00 b6 09 00 00 00    	add    BYTE PTR [rsi+0x9],dh
  202075:	00 00                	add    BYTE PTR [rax],al
  202077:	00 c6                	add    dh,al
  202079:	09 00                	or     DWORD PTR [rax],eax
  20207b:	00 00                	add    BYTE PTR [rax],al
  20207d:	00 00                	add    BYTE PTR [rax],al
  20207f:	00 d6                	add    dh,dl
  202081:	09 00                	or     DWORD PTR [rax],eax
  202083:	00 00                	add    BYTE PTR [rax],al
  202085:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .data:

0000000000202088 <__data_start>:
	...

0000000000202090 <__dso_handle>:
  202090:	90                   	nop
  202091:	20 20                	and    BYTE PTR [rax],ah
  202093:	00 00                	add    BYTE PTR [rax],al
  202095:	00 00                	add    BYTE PTR [rax],al
	...

Disassembly of section .bss:

00000000002020a0 <stdout@@GLIBC_2.2.5>:
	...

00000000002020b0 <stdin@@GLIBC_2.2.5>:
	...

00000000002020c0 <stderr@@GLIBC_2.2.5>:
	...

00000000002020c8 <completed.7698>:
	...

Disassembly of section .comment:

0000000000000000 <.comment>:
   0:	47                   	rex.RXB
   1:	43                   	rex.XB
   2:	43 3a 20             	rex.XB cmp spl,BYTE PTR [r8]
   5:	28 55 62             	sub    BYTE PTR [rbp+0x62],dl
   8:	75 6e                	jne    78 <_init-0x860>
   a:	74 75                	je     81 <_init-0x857>
   c:	20 37                	and    BYTE PTR [rdi],dh
   e:	2e 35 2e 30 2d 33    	cs xor eax,0x332d302e
  14:	75 62                	jne    78 <_init-0x860>
  16:	75 6e                	jne    86 <_init-0x852>
  18:	74 75                	je     8f <_init-0x849>
  1a:	31 7e 31             	xor    DWORD PTR [rsi+0x31],edi
  1d:	38 2e                	cmp    BYTE PTR [rsi],ch
  1f:	30 34 29             	xor    BYTE PTR [rcx+rbp*1],dh
  22:	20 37                	and    BYTE PTR [rdi],dh
  24:	2e                   	cs
  25:	35                   	.byte 0x35
  26:	2e 30 00             	xor    BYTE PTR cs:[rax],al
