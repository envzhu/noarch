.section .data
msg:
  .asciz  "Hello World!\n"

.section .text
.globl _start
_start:
  mov $1,%rax     # write
  mov $1,%rdi     # stdout
  mov $msg,%rsi   # string address
  mov $13,%rdx    # length
  syscall

  mov $60,%rax    # exit
  mov $0,%rdi # status
  syscall
