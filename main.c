#define PACKAGE "bfd"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bfd.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long int u64;

#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))

/* Helper functions for binary operations */
void
print_binary(u8 n) {
  for (int i = 1; i < (1 << 7); i <<= 1) {
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

/* Gets len bits at index [i,j] (i > j) */
u32
u32_get_bits(u32 n, int i, int j) {
  u32 big = (1 << (i+1));
  u32 sml = (1 << (j));
  return (n & (big-sml)) >> j;
}

//#if 0
/* Struct containing decoded op(mov) information */
typedef struct {
  u32 sf   : 1;
  u32 opc  : 2;
  u32 code : 6;
  u32 hw   : 2;
  u32 imm  : 16;
  u32 rd   : 5;
} insns, *p_insns;

/* Method to decode the insns op(u32) into sf, opc, code, hw, imm and rd
 * according to the struct above
 * https://github.com/CAS-Atlantic/AArch64-Encoding/blob/master/binary%20encodding.pdf
 * for further details */
void
decode_op(u32 op, u32 *sf, u32 *opc, u32 *code, u32 *hw, u32 *imm, u32 *rd) {
  //*sf   = (op & 0x80000000) >> 31;    // byte  [31]
  *sf   = u32_get_bits(op, 31, 1);
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
//#endif
#if 0
/* Contains the information inside an insns in the form of
 * name: value (example: sf: 1) */
typedef struct {
  char *name;
  u32 val;
} symbol, *p_symbol;

/* Contains the whole encoding of the u32 insns */
typedef struct {
  u32 u_insns;
  p_symbol syms;
  int n_syms;
} insns, *p_insns;

void set_insns(p_insns pin, u32 u_insns) {
  pin->u_insns = u_insns;
}
#endif

p_insns
create_insns(void) {
  p_insns pin = (p_insns)malloc(sizeof(insns));
  //set_insns(pin, op);
  //pin->n_syms = 32;
  //pin->syms = (p_symbol)malloc(sizeof(symbol) * pin->n_syms);
  //memset(pin->syms, 0, sizeof())
  return pin;
}

/* The opcode identification technique is the same as
 * the one binutils uses.
 * We use the bitwise-AND to find bits that contain the
 * opcode of the instruction and identify through there.
 * More info at
 * https://developer.arm.com/documentation/ddi0487/latest/ */
typedef enum {
  ADR,
  MOV,
  MOVZ,
  SVC,
  UNK
} insns_t;

typedef struct {
  u32 value, mask; // identify insns if op&mask == value
  insns_t disas;
} opcode;

static opcode opcodes[] = {
  {0x10000000, 0x9f000000, ADR},
  {0x2a0003e0, 0x7fe0ffe0, MOV},
  {0x52800000, 0x7f800000, MOVZ},
  {0xd4000001, 0xffe0001f, SVC},
  {0x00000000, 0x00000000, UNK}
};

static char *disas[] = {
  "adr{immlo:[30-29],immhi:[23-5],rd:[4-0]}",
  "mov{sf:[31],rm:[20-16],rd:[4-0]",
  "movz{sf:[31],hw:[22-21],imm16:[20-5],rd:[4-0]}",
  "svc{imm16:[20-5]}",
  "unidentified instruction"
};

insns_t
get_opcode(u32 insn) {
  opcode *op = opcodes;
  while(op->value) {
    if ((op->mask & insn) == op->value)
      return op->disas;
    op++;
  }
  return UNK;
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

  u8 *buf[4];
  p_insns pin = create_insns();

  int j=0;

  struct bfd_section *s = input_bfd->sections;
  do {
    printf("\n");
    printf("[%d] %s\t%x\t%x\t%x\n",
        s->id, s->name, (u32)s->vma, (u32)s->lma, (u32)s->size);
    
    buf[j] = (u8 *)malloc(s->size);
    if(buf[j] == NULL) {
      fprintf(stderr, "Failed to malloc size: %d bytes\n", s->size);
      goto end;
    }

    if(bfd_get_section_contents(input_bfd, s, buf[j], 0, s->size)
        == FALSE) {
      bfd_perror("BFD GET SECTION CONTENTS ERROR\n");
      j++;
      goto end;
    }
    
    for (int i=0; i<s->size; i+=4) {
      printf("%02x %02x %02x %02x\t%c.%c.%c.%c\t",
          buf[j][i], buf[j][i+1], buf[j][i+2], buf[j][i+3],
          buf[j][i], buf[j][i+1], buf[j][i+2], buf[j][i+3]);
      for (int k=0; k<4; k++) {
        print_binary(buf[j][i+k]);
        printf(" ");
      }
      set_insns(pin, buf[j]+i);
      //printf("\tsf:%01x opc:%01x code:%02x hw:%01x imm:%04x reg:%01x",
      //    pin->sf, pin->opc, pin->code, pin->hw, pin->imm, pin->rd);
      insns_t ins = get_opcode(buf_to_u32(buf[j]+i));
      printf("\t%s", disas[ins]);
      printf("\n");
    }
    j++;
  } while ((s = s->next) != NULL);

end:
  for(int i=0; i<j; i++)
    free(buf[i]);
  free(pin);
  bfd_close(input_bfd);

  return 0;
}
