#include <capstone/capstone.h>

void print_cs_arm64_detail(csh handle, cs_detail *detail);

/* Receives arm64 insn and printf's the translation */
void translate_from_arm64_to_x64(cs_insn *insn);
