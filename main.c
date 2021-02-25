#define PACKAGE "bfd"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bfd.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long int u64;


/* Helper functions for binary operations */
void
print_binary(u8 n) {
  for (int i = 1 << 7; i > 0; i >>= 1) {
    (n & i) ? printf("1") : printf("0");
  }
}

u32
buf_to_u32(u8 op[]) {
  u32 u = 0;
  u += op[0];
  u += (1 << 8) * op[1];
  u += (1 << 16) * op[2];
  u += (1 << 24) * op[3];
  return u;
}

/* Struct containing decoded op(mov) information */
typedef struct INSNS {
  u32 sf   : 1;
  u32 opc  : 2;
  u32 code : 6;
  u32 hw   : 2;
  u32 imm  : 16;
  u32 rd   : 5;
} insns, *p_insns;

/* Method to decode the insns op(u32) into sf, opc, code, hw, imm and rd
 * according to the struct above */
void
decode_op(u32 op, u32 *sf, u32 *opc, u32 *code, u32 *hw, u32 *imm, u32 *rd) {
  *sf   = (op & 0x80000000) >> 31;    // byte  [31]
  *opc  = (op & 0x60000000) >> 29;    // bytes [30-29]
  *code = (op & 0x1f800000) >> 23;    // bytes [28-23]
  *hw   = (op & 0x00600000) >> 21;    // bytes [22-21]
  *imm  = (op & 0x001fffe0) >> 5;     // bytes [20-5]
  *rd   = (op & 0x0000001f);          // bytes [0-4]
}

void
set_insns(p_insns pin, u8 op[]) {
  memset(pin, 0, sizeof(&pin));

  u32 sf, opc, code, hw, imm, rd;
  u32 d_op = buf_to_u32(op);
  decode_op(d_op, &sf, &opc, &code, &hw, &imm, &rd);
  pin->sf = sf;
  pin->opc = opc;
  pin->code = code;
  pin->hw = hw;
  pin->imm = imm;
  pin->rd = rd;
}

p_insns
create_insns(void) {
  p_insns pin = (p_insns)malloc(sizeof(insns));
  //set_insns(pin, op);
  return pin;
}

int
main (int argc, char *argv[]) {

  if (argc < 2)
    return -1;

  bfd_init();

  bfd *input_bfd = bfd_openr(argv[1], "elf64-little");
  if (input_bfd == NULL) {
    bfd_perror("BFD OPENR ERROR\n");
    return -1;
  }

  if (!bfd_check_format(input_bfd, bfd_object)) {
    bfd_perror("BFD CHECK FORMAT ERROR\n");
    bfd_close(input_bfd);
    return -1;
  }

  u8 buf[32];
  p_insns pin = create_insns();

  struct bfd_section *s = input_bfd->sections;
  do {
    printf("\n");
    printf("[%d] %s\t%x\t%x\t%x\n",
        s->id, s->name, (u32)s->vma, (u32)s->lma, (u32)s->size);
    bfd_get_section_contents(input_bfd, s, buf, 0, 16);
    for (int i=0; i<sizeof(buf); i+=4) {
      printf("%02x %02x %02x %02x\t", buf[i], buf[i+1], buf[i+2], buf[i+3]);
      for (int j=0; j<4; j++) {
        print_binary(buf[i+j]);
        printf(" ");
      }
      set_insns(pin, buf+i);
      printf("\tsf:%01x opc:%01x code:%01x hw:%01x imm:%02x reg:%01x",
          pin->sf, pin->opc, pin->code, pin->hw, pin->imm, pin->rd);
      printf("\n");
    }
  } while ((s = s->next) != NULL);

  free(pin);
  bfd_close(input_bfd);

  return 0;
}
