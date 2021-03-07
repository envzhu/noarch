#include <stdio.h>
#include <string.h>
#include <capstone/capstone.h>

#include "lib.h"


typedef char *(trans_insn_fn_t)(cs_insn *insn);

trans_insn_fn_t trans_mov;
trans_insn_fn_t trans_movz;
trans_insn_fn_t trans_adr;
trans_insn_fn_t trans_svc;

static trans_insn_fn_t *trans_insn_fn_table[] = {
  trans_mov,
  trans_movz,
  trans_adr,
  trans_svc
};

static char* insn_table[] = {
  "mov",
  "movz",
  "adr",
  "svc"
};

void translate_from_arm64_to_x64(cs_insn *insn) {
  char t_insn[64];
  unsigned int reg;

  int i;
  for (i=0; i<4; ++i) {
    if (strcmp(insn->mnemonic, insn_table[i]) == 0)
      break;
  }
  if (i == 4)
    return;

  printf("\tTranslated : %s\n", trans_insn_fn_table[i](insn)); 
   
}
/*
convert_reg_from_arm64_to_x64(){

}
*/
char *trans_mov(cs_insn *insn) {
  
  return "movq";
}
char *trans_movz(cs_insn *insn) {
  return "movq";
}
char *trans_adr(cs_insn *insn) {
  return "movq";
}
char *trans_svc(cs_insn *insn) {
  return "syscall";
}

void print_cs_arm64_detail(csh handle, cs_detail *detail) {
  
  if (detail->regs_read_count > 0) {
    printf("\tImplicit registers read: ");
    for (int n = 0; n < detail->regs_read_count; n++) {
      printf("%s ", cs_reg_name(handle, detail->regs_read[n]));
    }
    printf("\n");
  }
  if (detail->regs_write_count > 0) {
    printf("\tImplicit registers write: ");
    for (int n = 0; n < detail->regs_write_count; n++) {
      printf("%s ", cs_reg_name(handle, detail->regs_write[n]));
    }
    printf("\n");
  }

  if (detail->arm64.op_count)
    printf("\tNumber of operands: %u\n", detail->arm64.op_count);

  for (int n = 0; n < detail->arm64.op_count; n++) {
    cs_arm64_op *op = &(detail->arm64.operands[n]);
    switch(op->type) {
      case ARM64_OP_REG:
        printf("\t\toperands[%u].type: REG = %s (%u)\n", n, cs_reg_name(handle, op->reg), op->reg);
        break;
      case ARM64_OP_IMM:
        printf("\t\toperands[%u].type: IMM = 0x%x\n", n, op->imm);
        break;
      case ARM64_OP_FP:
        printf("\t\toperands[%u].type: FP = %f\n", n, op->fp);
        break;
      case ARM64_OP_MEM:
        printf("\t\toperands[%u].type: MEM\n", n);
        if (op->mem.base != ARM64_REG_INVALID)
          printf("\t\t\toperands[%u].mem.base: REG = %s\n", n, cs_reg_name(handle, op->mem.base));
        if (op->mem.index != ARM64_REG_INVALID)
          printf("\t\t\toperands[%u].mem.index: REG = %s\n", n, cs_reg_name(handle, op->mem.index));
        if (op->mem.disp != 0)
          printf("\t\t\toperands[%u].mem.disp: 0x%x\n", n, op->mem.disp);
        break;
      case ARM64_OP_CIMM:
        printf("\t\toperands[%u].type: C-IMM = %u\n", n, op->imm);
        break;
    }

    if (op->shift.type != ARM64_SFT_INVALID && op->shift.value)
      printf("\t\t\tShift: type = %u, value = %u\n", op->shift.type, op->shift.value);

    if (op->ext != ARM64_EXT_INVALID)
      printf("\t\t\tExt: %u\n", op->ext);
  }

  if (detail->arm64.cc != ARM64_CC_INVALID)
    printf("\tCode condition: %u\n", detail->arm64.cc);

  if (detail->arm64.update_flags)
    printf("\tUpdate-flags: True\n");

  if (detail->arm64.writeback)
    printf("\tWrite-back: True\n");

}


