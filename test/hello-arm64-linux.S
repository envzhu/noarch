.text

.global _start
_start:
  mov     x2,  #13    // x2  length
  adr     x1,  msg    // x1  string address
  mov     x0,  #1     // x0  stdout
  mov     x8,  #64
  svc     #0          // sys_write
  mov     x0,  xzr
  mov     x8,  #93
  svc     #0          // exit
msg:
  .asciz  "Hello World!\n"
