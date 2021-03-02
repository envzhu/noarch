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

/* Contains the information inside an insns in the form of
 * name: value (example: sf: 1) */

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
  "adr{sf[31-31],immlo[30-29],immhi[23-5],rd[4-0],}",
  "mov{sf[31-31],rm[20-16],rd[4-0],",
  "movz{sf[31-31],hw[22-21],imm16[20-5],rd[4-0]},",
  "svc{imm16[20-5],}",
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

typedef struct {
  u32 val;
  char name[32];
} symbol, *p_symbol;

/* Contains the whole encoding of the u32 insns */
typedef struct {
  u32 u_insns;
  symbol syms[32];
  //int n_syms;
} insns, *p_insns;

void
set_symbols(symbol syms[], u32 u_insns) {
  memset(syms, 0, sizeof(symbol) * 32);
  insns_t op = get_opcode(u_insns);
  if (op == UNK) return;


  char *dis = disas[op];
  char n[32];
  int big, small;
  int i = 0;
  int j = 0;
  while(*dis != '\0') {
    //printf("\ni:%d\tj:%d\t*dis:%c", i, j, *dis);
    switch(*dis) {
      case ' ':
        break;
      case ',':
        syms[j].val = u32_get_bits(u_insns, big, small);
        //printf("\nbig:%x,small:%x,u32:%x\n", big, small, syms[j].val);
        j++;
        break;
      case '[':
        n[i] = '\0';
        strcpy(syms[j].name, n);
        //printf("\nname:%s", syms[j].name);
        i = 0;
        break;
      case '-':
        n[i] = '\0';
        big = atoi(n);
        i = 0;
        break;
      case ']':
        n[i] = '\0';
        small = atoi(n);
        i = 0;
        break;
      case '{':
        n[i] = '\0';
        strcpy(syms[j].name, n);
        //printf("\nname:%s, n:%s, syms[j]:%p", syms[j].name, n, syms+i);
        //printf("\n");
        i = 0;
        j++;
        break;
      case '}':
        break;
      default:
        n[i] = *dis;
        i++;
    }
    dis++;
  }
}

void
set_insns(p_insns pin, u32 u_insns) {
  pin->u_insns = u_insns;
  set_symbols(pin->syms, u_insns);
}

p_insns
create_insns(void) {
  p_insns pin = (p_insns)malloc(sizeof(insns));
  //set_insns(pin, op);
  //pin->n_syms = 32;
  //pin->syms = (p_symbol)malloc(sizeof(symbol) * pin->n_syms);
  //memset(pin->syms, 0, pin->n_syms * sizeof(symbol));
  return pin;
}

void
print_symbols(p_insns pin) {
  if (pin->syms[0].name[0] == '\0')
    return;

  printf("%s=> ", pin->syms[0].name);
  for (int i=1; i<32; ++i) {
    symbol s = pin->syms[i];
    if (s.name[0] == '\0')
      break;
    printf("%s: %d,", s.name, s.val);
  }
  printf("\n");
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

  int sec=0;

  struct bfd_section *s = input_bfd->sections;
  do {
    printf("\n");
    printf("[%d] %s\t%lx\t%lx\t%lx\t%x\n",
        s->id, s->name, s->vma, s->lma, s->size, s->flags);

    buf[sec] = (u8 *)malloc(s->size);
    if(buf[sec] == NULL) {
      fprintf(stderr, "Failed to malloc size: %lu bytes\n", s->size);
      goto end;
    }

    if(bfd_get_section_contents(input_bfd, s, buf[sec], 0, s->size)
        == FALSE) {
      bfd_perror("BFD GET SECTION CONTENTS ERROR\n");
      sec++;
      goto end;
    }

    for (int i=0; i<s->size; i+=4) {
      printf("%02x %02x %02x %02x\t%c.%c.%c.%c\t",
          buf[sec][i], buf[sec][i+1], buf[sec][i+2], buf[sec][i+3],
          buf[sec][i], buf[sec][i+1], buf[sec][i+2], buf[sec][i+3]);
      for (int k=0; k<4; k++) {
        print_binary(buf[sec][i+k]);
        printf(" ");
      }
      if (s->flags & SEC_CODE) {
        set_insns(pin, buf_to_u32(buf[sec]+i));
        print_symbols(pin);
      }
      printf("\n");
    }
    sec++;
  } while ((s = s->next) != NULL);

end:
  for(int i=0; i<sec; i++)
    free(buf[i]);

  free(pin);
  bfd_close(input_bfd);

  return 0;
}
