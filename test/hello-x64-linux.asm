
./hello-x64-linux.elf:	file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <_start>:
  401000: 48 c7 c0 01 00 00 00         	movq	$1, %rax
  401007: 48 c7 c7 01 00 00 00         	movq	$1, %rdi
  40100e: 48 c7 c6 00 20 40 00         	movq	$4202496, %rsi
  401015: 48 c7 c2 0d 00 00 00         	movq	$13, %rdx
  40101c: 0f 05                        	syscall
  40101e: 48 c7 c0 3c 00 00 00         	movq	$60, %rax
  401025: 48 c7 c7 00 00 00 00         	movq	$0, %rdi
  40102c: 0f 05                        	syscall
