.section .data
msg:
  .asciz  "Hello World!\n"

.section .text
.global _start

_start:
  // sys_write(stdout, msg, 13)
  mov     x2,  #13    // x2  length
  adr     x1,  msg    // x1  string address
  mov     x0,  #1     // x0  stdout
  mov     x8,  #64    // syscall number for write is 0x40 (64)
  svc     #0          // sys_write
  // exit(xzr)
  mov     x0,  xzr
  mov     x8,  #93
  svc     #0          // exit
