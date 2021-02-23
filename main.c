#define PACKAGE "bfd"
#include <stdio.h>
#include <bfd.h>

int main (int argc, char *argv[]) {
  FILE *input_fp = fopen(argv[1], 'r');
  FILE *output_fp = fopen(argv[2], 'w');
  if ( input_fp == NULL || output_fp == NULL)
    return -1;
  
}
