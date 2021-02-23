#define PACKAGE "bfd"
#include <stdio.h>
#include <bfd.h>

int main (int argc, char *argv[]) {
  bfd_init();
  bfd *abfd = bfd_openr(fname, "elf64-x86-64");
  FILE *input_fp = fopen(argv[1], 'r');
  FILE *output_fp = fopen(argv[2], 'w');
  if ( input_fp == NULL || output_fp == NULL)
    return -1;
}
