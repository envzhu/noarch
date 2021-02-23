#define PACKAGE "bfd"
#include <stdio.h>
#include <bfd.h>

int main (int argc, char *argv[]) {

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

  unsigned char buf[16];

  struct bfd_section *s = input_bfd->sections;
  do {
    printf("\n");
    printf("[%d] %s\t%x\t%x\t%x\n", s->id, s->name, s->vma, s->lma, s->size);
    bfd_get_section_contents(input_bfd, s, buf, 0, 16);
    for (int i=0; i<16; ++i)
      printf("%02x ", buf[i]);
  } while ((s = s->next) != NULL);

  bfd_close(input_bfd);

  return 0;
}
