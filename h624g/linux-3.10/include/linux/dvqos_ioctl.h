#ifndef __DVQOS_IOCTL_H__
#define __DVQOS_IOCTL_H__

// DVQOS_OP_GETREGS : arg is QOS_REGS_LEN(260) length byte array
#define DVQOS_OP_GETREGS  1
#define DVQOS_OP_READREG  2
#define DVQOS_OP_WRITEREG 3

// arg of READREG/WRITEREG
struct qos_reg_t {
	int          reg;
	unsigned int val;
};

#endif // __DVQOS_IOCTL_H__

