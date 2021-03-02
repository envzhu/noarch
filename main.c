#define PACKAGE "bfd"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bfd.h>
#include <capstone/capstone.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long int u64;

u32
buf_to_u32(u8 op[]) {
  u32 u = 0;
  u += op[0];
  u += (1 << 8) * op[1];
  u += (1 << 16) * op[2];
  u += (1 << 24) * op[3];
  return u;
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

	csh handle;
	cs_insn *insn;
	size_t count;

  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
    fprintf(stderr, "Failed to open capstone in ARM64v8 MODE\n");
    return -1;
  }

  u8 *buf[4];
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
      printf("\n");

      if (s->flags & SEC_CODE) {
        count = cs_disasm(handle, buf[sec]+i, 3, 0x1000, 0, &insn);
        if (count > 0) {
          size_t j;
          for (j = 0; j < count; j++) {
            printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
            insn[j].op_str);
          }
        cs_free(insn, count);
        } else
        printf("ERROR: Failed to disassemble given code!\n");
      }
    }
    sec++;
  } while ((s = s->next) != NULL);

end:
  for(int i=0; i<sec; i++)
    free(buf[i]);

  bfd_close(input_bfd);

  return 0;
}
