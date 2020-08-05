#ifndef __QOS_REG_H__
#define __QOS_REG_H__

unsigned int read_qos_reg(int off);
void write_qos_reg(int off, unsigned int val);
void set_qos_reg32(int off, unsigned int clr, unsigned int nv);

#define QOS_IBCR0     0x04
#define QOS_IBCR3     0x10
#define QOS_8021Q2LTM 0x30
#define QOS_QNUMCR    0x54
#define QOS_8021PRMCR 0x6c
#define QOS_DSCPRM0   0x70
#define QOS_DSCPRM1   0x74
#define QOS_RLRC	  0x78
#define QOS_P0Q0RGCR  0x100
#define QOS_WFQRCRP0  0x1b0
#endif
