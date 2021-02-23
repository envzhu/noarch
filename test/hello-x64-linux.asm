
./hello-x64-linux.elf:	file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <msg>:
  401000: 48 65                        	gs
  401002: 6c                           	insb	%dx, %es:(%rdi)
  401003: 6c                           	insb	%dx, %es:(%rdi)
  401004: 6f                           	outsl	(%rsi), %dx
  401005: 20 57 6f                     	andb	%dl, 111(%rdi)
  401008: 72 6c                        	jb	0x401076 <_start+0x68>
  40100a: 64 21 0a                     	andl	%ecx, %fs:(%rdx)
  40100d: 00 48 c7                     	addb	%cl, -57(%rax)

000000000040100e <_start>:
  40100e: 48 c7 c0 01 00 00 00         	movq	$1, %rax
  401015: 48 c7 c7 01 00 00 00         	movq	$1, %rdi
  40101c: 48 c7 c6 00 10 40 00         	movq	$4198400, %rsi
  401023: 48 c7 c2 0d 00 00 00         	movq	$13, %rdx
  40102a: 0f 05                        	syscall
  40102c: 48 c7 c0 3c 00 00 00         	movq	$60, %rax
  401033: 48 c7 c7 00 00 00 00         	movq	$0, %rdi
  40103a: 0f 05                        	syscall
