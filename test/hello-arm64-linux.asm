
./hello-arm64-linux.elf:	file format elf64-littleaarch64


Disassembly of section .text:

0000000000400078 <_start>:
  400078: a2 01 80 d2  	mov	x2, #13
  40007c: e1 00 00 10  	adr	x1, #28
  400080: 20 00 80 d2  	mov	x0, #1
  400084: 08 08 80 d2  	mov	x8, #64
  400088: 01 00 00 d4  	svc	#0
  40008c: e0 03 1f aa  	mov	x0, xzr
  400090: a8 0b 80 d2  	mov	x8, #93
  400094: 01 00 00 d4  	svc	#0

0000000000400098 <msg>:
  400098:	48 65 6c 6c	.word	0x6c6c6548
  40009c:	6f 20 57 6f	.word	0x6f57206f
  4000a0:	72 6c 64 21	.word	0x21646c72
  4000a4:	0a 00		.short	0x000a
