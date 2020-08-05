#ifndef __QOS_REG_H__
#define __QOS_REG_H__

unsigned int read_qos_reg(int off);
void write_qos_reg(int off, unsigned int val);
void set_qos_reg32(int off, unsigned int clr, unsigned int nv);

				/* ====== Base - 0xBB80-4700 ====== */
#define QOS_IBCR0	0x04	/* Ingress Bandwidth Control Register 0 */
#define QOS_8021Q2LTM	0x30	/* 802.1Q priority To Linear priority Transfer Mapping */
#define QOS_QNUMCR	0x54	/* Queue Number Control Register */
#define QOS_8021PRMCR	0x6c	/* 802.1P Remarking Control Rester */
#define QOS_DSCPRM0	0x70	/* DSCP Remarking Control Register 0 */
#define QOS_DSCPRM1	0x74	/* DSCP Remarking Control Register 1 */
#define QOS_RLRC	0x78	/* Remarking Layer Rule Control */

				/* ====== Base - 0xBB80-4800 ====== */
#define QOS_P0Q0RGCR	0x100	/* Rate Guarantee Control Register of Port 0 Queue 0 - offset from 0xBB80-4700 */
#define QOS_WFQRCRP0	0x1b0	/* Weighted Fair Queue Rate Control Register of Port 0 */
#endif

