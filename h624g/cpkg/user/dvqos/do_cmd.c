#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <bcmnvram.h>
#include <brdio.h>
#include <shutils.h>
#include "dvqos.h"
#include "qos_reg.h"
#include "do_cmd.h"


#define ON  1
#define OFF 0
#define SPQ 0
#define WFQ 1

extern int verbose;

static void qos_1q_2_ipri(int pri_1q, int pri_i)
{
	unsigned int val, mask;

	if (pri_1q == -1) {
		// revert to default value
		write_qos_reg(QOS_8021Q2LTM, 0x00FAC642);
		return;
	}
	mask = (0x07 << (pri_1q * 3));

	val = pri_i << (pri_1q * 3);
	set_qos_reg32(QOS_8021Q2LTM, ~mask, val);
}

void qos_port_usage(char *cmd)
{
	fprintf(stderr, "%s port p# enable|disable\n", cmd);
	fprintf(stderr, "%s port p# inrate|outrate rate(kbps)\n", cmd);
	fprintf(stderr, "%s port p# q q# spq|wfq avg(kbps) weight [[peak] L1]\n", cmd);
}

static int qos_port_enable(int port, char *cmd)
{
	// enable: set output queue number to 4
	// disable: set output queue number to 1
	/*
	20150606 jcode#0
	caution!!! change Q4 register(Q4: 0x100 => 0x11)
	*/
	unsigned int val, mask;

	mask = (0x07 << (port * 3));

	if (cmd[0] == 'e') {
		val = 3 << (port * 3);
	} else {
		val = 1 << (port * 3);
	}
	set_qos_reg32(QOS_QNUMCR, ~mask, val);
	return 1;
}

int qos_port_rate(int port, char *cmd, int rate_16k)
{
	int reg;
	unsigned int mask, val;

	if (cmd[0] == 'i') {
		// ingress
		if ((port < 0) || (port >= 6))
			return 0;

		reg = QOS_IBCR0 + 4 * (port / 2);
		port = port % 2;
		mask = (0x0000ffff) << ((port & 1) * 16);
		val = (rate_16k & 0x0000ffff) << ((port & 1) * 16);	// val==0 use line rate
		set_qos_reg32(reg, ~mask, val);
	} else {
		// egress (WFQ rate control)
		if ((port < 0) || (port >= 7))
			return 0;
		reg = QOS_WFQRCRP0 + 12 * port;
		val = rate_16k / 4;	// unit 64k
		if (val == 0) {
			unsigned int phy_status = switch_port_status(port);
// GAPNRTL-83
// change Total Bandwidth of Weighted fair queue
			if (phy_status & PHF_LINKUP) {
				if (phy_status & PHF_10M) {	// 10M
					val = 0x00a0;	// 0xa0 * 64K = 10240
				} else if (phy_status & PHF_100M) {// 100M
					val = 0x0640;	// 0x640 * 64K = 102400
				} else if (phy_status & PHF_500M) {// 500M
					val = 0x1f40;	//0x1f40 * 64K = 512000
				} else {			// 1000M
					val = 0x3fff;	// disable out rate control
				}
			} else {
				val = 0x3fff;	// disable out rate control
			}
		}
		write_qos_reg(reg, val);
	}
	return 1;
}

static int conv_sys_q(int q)
{
	switch (q) {
	case 0:
		return 0;
	case 1:
		return 1;
	case 2:
		return 2;
	case 3:
		return 5;
	}
	return 0;
}


#define QT_WFQ_REGVAL	0x80
#define QT_SPQ_REGVAL	0x0
static int qos_port_q(int port, int q, int type,    int avg_64k, int weight,   int peak, int l1)
{
	unsigned int v =0 , m =0;
	int reg;

	if (q < 0 || q >= 4)
		return 0;

	q = conv_sys_q(q);
/*
Per-Queue Rate Guarantee Control Register (Base: 0xBB80_4800)
[26:24] Peak Packet Rate of PPR LB in Times of APR. (To disable rate 0x7)
[23:16] Bucket Burst Size of APR LB in Bytes. (To disable rate 0xff)
[13:0]  Average Packet Rate of APR LB in Times of 64Kbps. (To disable rate 0x3fff)
Unit=64kbps, Rate=PR[13:0]*64kbps
*/
	if (avg_64k == 0)
		avg_64k = 0x3fff;
	v = (peak & 0x07) << 24;
	v |= (l1 & 0x00ff) << 16;
	v |= (avg_64k & 0x3fff);
	reg = QOS_P0Q0RGCR + 4 * (port * 6 + q);

	write_qos_reg(reg, v);

/*
Minimal Rate Guarantee Control Register Address Mapping (Base:0xBB80_4800 + offset 0xB0)
caution!!!)
The weighting ratio between the multiple queues will be correct only when:
1) The traffic incomming port flow control is disable. Or
2) When flow control is enabled, the buffer and queue flow control threshold setting is in a non-blocking condition.
That is the summation of the multi-queue queued descriptior number (summation of OG_DSC_FCON) should not be larger than the
port Max limited descriptor threshold(P_MaxDSC_FCON), and should not be triggered by system descriptor flow control(S_DSC_FCON)
*/
	reg = QOS_WFQRCRP0 + 4 + (4 * port * 3);
	if (q >= 4) {
		reg += 4;
		q = q - 4;
	}
	v = (type == WFQ) ? QT_WFQ_REGVAL : QT_SPQ_REGVAL;
	v |= weight & 0x7f;
	v = v << (q * 8);
	m = 0x00ff << (q * 8);
	set_qos_reg32(reg, ~m, v);

	return 1;
}

int do_port(int argc, char *argv[])
{
	int port;
	int rate;

	if (argc < 2)
		return 0;

	port = strtoul(argv[0], NULL, 0);

	// parse sub-command
	if ((strcmp(argv[1], "enable") == 0) || (strcmp(argv[1], "disable") == 0)) {
		return qos_port_enable(port, argv[1]);
	} else if ((strcmp(argv[1], "inrate") == 0) || (strcmp(argv[1], "outrate") == 0)) {
		if (argc < 3)
			return 0;
		rate = strtoul(argv[2], NULL, 0) / 16;	// unit 16k
		return qos_port_rate(port, argv[1], rate);
	} else if (strcmp(argv[1], "q") == 0) {
		int a[6];
		if (argc < 6)
			return 0;
		a[4] = 0x07;
		a[5] = 0x00ff;
		a[0] = strtoul(argv[2], NULL, 0);
		if (strcmp(argv[3], "spq") == 0)
			a[1] = SPQ;
		else if (strcmp(argv[3], "wfq") == 0)
			a[1] = WFQ;
		else
			return 0;
		a[2] = strtoul(argv[4], NULL, 0) / 64;	// avg,  unit 64k
		a[3] = strtoul(argv[5], NULL, 0);	// weight
		if (argc >= 7)
			a[4] = strtoul(argv[6], NULL, 0);	// peak, unit #APR
		if (argc >= 8)
			a[5] = strtoul(argv[7], NULL, 0);	// L1 unit 1k, bucket burst size
		return qos_port_q(port, a[0], a[1], a[2], a[3], a[4], a[5]);
	} else {
		return 0;
	}
	return 1;
}

void qos_remark_usage(char *cmd)
{
	fprintf(stderr, "%s remark dscp port_bits pri0 pri1 pri2 pri3 pri4 pri5 pri6 pri7 : pri(0x00~0x3f)\n", cmd);
	fprintf(stderr, "%s remark 1q   port_bits pri0 pri1 pri2 pri3 pri4 pri5 pri6 pri7 : pri(0~7)\n", cmd);
}

static int qos_port_remark(int port_bits, char *cmd, int mval[8])
{
	unsigned int m, v;
	int i;

	if (verbose) {
		printf("qos_port_remark(0x%x, %s, %d,%d,%d,%d,%d,%d,%d,%d)\n", port_bits, cmd,
			   mval[0], mval[1], mval[2], mval[3], mval[4], mval[5], mval[6], mval[7]);
	}
	if (cmd[0] == '1') {
		if (port_bits == 0) {
			for (i = 0; i < 8; i++)
				mval[i] = i;
		}
		v = port_bits & 0x00ff;
		for (i = 0; i < 8; i++) {
			v = ((v << 3) & 0xfffffff8) | (mval[7 - i]);
		}
		write_qos_reg(QOS_8021PRMCR, v);

		m = 0x07;
		v = (port_bits ? 0x07 : 0);
		set_qos_reg32(QOS_RLRC, ~m, v);

	} else {
		if (port_bits == 0) {
			mval[0] = 0;
			mval[1] = 0;
			mval[2] = 0;
			mval[3] = 0;
			mval[4] = 0x2e;
			mval[5] = 0x2e;
			mval[6] = 0x2e;
			mval[7] = 0x2e;
		}
		v = (port_bits & 0x01ff) << 23;
		v = v | ((mval[7] & 0x3f) << 12);
		v = v | ((mval[6] & 0x3f) << 6);
		v = v | (mval[5] & 0x3f);
		write_qos_reg(QOS_DSCPRM1, v);
		v = ((mval[4] & 0x3f) << 24);
		v = v | ((mval[3] & 0x3f) << 18);
		v = v | ((mval[2] & 0x3f) << 12);
		v = v | ((mval[1] & 0x3f) << 6);
		v = v | (mval[0] & 0x3f);
		write_qos_reg(QOS_DSCPRM0, v);

		m = 0x07 << 3;
		v = (port_bits ? 0x07 : 0) << 3;
		set_qos_reg32(QOS_RLRC, ~m, v);
	}
	return 1;
}

int do_remark(int argc, char *argv[])
{
	int a[9];
	int i;

	if (argc < 10)
		return 0;

	if ((strcmp(argv[0], "dscp") == 0) || (strcmp(argv[0], "1q") == 0)) {
		for (i = 0; i < 9; i++)
			a[i] = strtoul(argv[1 + i], NULL, 0);
		return qos_port_remark(a[0], argv[0], &a[1]);
	}
	return 0;
}

#define MIN(a, b)	((a) < (b) ? (a) : (b))
#define MAX(a, b)	((a) > (b) ? (a) : (b))
#define RANGE(a, b, c)	MIN(MAX((a), (b)), (c))

#define QNUM	4

struct weight_group {
	int mbr, weight;
};

struct que_conf {
	int type[QNUM];
	int apr[QNUM];		/* Average Packet Rate */
	int weight[QNUM];	/* Weight */
	int numgrp;		/* Weight Group Number */
	struct weight_group wg[QNUM];
	int wgpos[QNUM];
};
//        port Q       apg  weight
//x_QOS_Q_ 0 _ 0 = W_   0  _  8
static void compute_weight(struct que_conf *q, int port)
{
	char name[32], buf[64];
	char *args[10];
	int i, j, remains, sum = 0;
	int low, high = -1;

	memset(q, 0, sizeof(*q));
	for (i = sum = 0; i < QNUM; i++) {
		sprintf(name, "x_QOS_Q_%d_%d", port, i);
		nvram_get_r_def(name, buf, sizeof(buf), "S_0_1");
		if (sep_str(buf, args, sizeof(args) / sizeof(char *), "_") == 3) {
			q->type[i] = (toupper(args[0][0]) == 'W') ? WFQ : SPQ;
			q->apr[i] = strtoul(args[1], NULL, 10) / 64;
			if (q->type[i] == WFQ) {
				j = strtoul(args[2], NULL, 10);
				q->weight[i] = RANGE(j, 1, 128);
				sum += q->weight[i];
			}
		} else {
			q->type[i] = -1;
			fprintf(stderr, "error %s, check value!!!\n", name);
		}
	}

	if (sum == 0)
		return;

	/* Calculate Ratio with loss */
	j = sum;
	for (i = sum = 0; i < QNUM; i++) {
		if (q->type[i] != WFQ)
			continue;
		q->weight[i] = (q->weight[i] * 128) / j;
		sum += q->weight[i];
		if (high < 0)
			high = low = i;
		else if (q->weight[high] < q->weight[i])
			high = i;
		else if (q->weight[low] > q->weight[i])
			low = i;
	}

	/* Grouping */
	for (i = 0; i < QNUM; i++) {
		if (q->type[i] != WFQ)
			continue;
		for (j = 0; j < q->numgrp; j++) {
			if (q->wg[j].weight == q->weight[i]) {
				q->wg[j].mbr += 1;
				q->wgpos[i] = j;
				break;
			}
		}

		if (j >= q->numgrp) {
			q->wg[q->numgrp].mbr = 1;
			q->wg[q->numgrp].weight = q->weight[i];
			q->wgpos[i] = q->numgrp;
			q->numgrp++;
		}
	}

	if (q->numgrp == 1)
		memset(q->weight, 0, sizeof(q->weight));
	else {
		remains = 128 - sum;
		if (remains && q->wg[q->wgpos[high]].mbr == remains) {
			q->weight[high] += 1;
			for (i = 0; i < QNUM; i++) {
				if (q->type[i] != WFQ || i == high)
					continue;
				if (q->wgpos[high] == q->wgpos[i])
					q->weight[i] += 1;
			}
		} else {
			/* Special case #1 */
			if (remains == 2 &&
				(q->weight[low] == (128 / 10) && q->weight[high] == (128 >> 1)) &&
				(q->wg[q->wgpos[low]].mbr == 1 && q->wg[q->wgpos[high]].mbr == 1)) {
				q->weight[high] += 3;
				q->weight[low] -= 1;
			} else if (remains > 1) {
				/* Special case #2 */
				for (i = 0; i < q->numgrp; i++) {
					if (q->wg[i].mbr != remains || i == q->wgpos[low])
						continue;
					for (j = 0; j < QNUM; j++) {
						if (q->type[j] != WFQ)
							continue;
						if (q->wgpos[j] == i)
							q->weight[j] += 1;
					}
					break;
				}
			}
		}
		/* Put the highest weight plus up to 128,  */
		for (i = j = 0; i < 4; i++)
			j += q->weight[i];
		q->weight[high] += (128 - j);
		/* Check overrun */
		if ((q->weight[high] & 0x7f) == 0)
			q->weight[high] = 128 - 1;
	}
}

void qos_port_apply(void)
{
	// QOS_Q_P#_Q#     TYPE_AVGRATE_WEIGHT
	// QOS_ENABLE_P#   VAL
	// QOS_RATE_DIR_P# RATE
	int i, j;
	char n[20], v[40];
	struct que_conf qc;

	for (i = 0; i < 5; i++) {
		sprintf(n, "x_QOS_ENABLE_%d", i);
		nvram_get_r_def(n, v, sizeof(v), "0");
		if (v[0] == '0')
			qos_port_enable(i, "disable");
		else
			qos_port_enable(i, "enable");

		sprintf(n, "x_QOS_RATE_ENABLE_%d", i);
		nvram_get_r_def(n, v, sizeof(v), "0");
		if (strcmp(v, "0")) {	//0 = disable, 1=enable
			sprintf(n, "x_QOS_RATE_I_%d", i);
			nvram_get_r_def(n, v, sizeof(v), "0");
			qos_port_rate(i, "inrate", atoi(v) / 16);

			sprintf(n, "x_QOS_RATE_O_%d", i);
			nvram_get_r_def(n, v, sizeof(v), "0");
			qos_port_rate(i, "outrate", atoi(v) / 16);
		} else {
			qos_port_rate(i, "inrate", 0);
			qos_port_rate(i, "outrate", 0);
		}

		compute_weight(&qc, i);
		for (j = 0; j < 4; j++) {
			if (qc.type[j] < 0)
				continue;
			qos_port_q(i, j, qc.type[j], qc.apr[j], qc.weight[j], 0x07, 0x00ff);
		}
	}
}

void qos_remark_apply(void)
{
	// QOS_RM_DSCP  PORTBITS_P0_P1_P2_P3_P4_P5_P6_P7
	// QOS_RM_1Q    PORTBITS_P0_P1_P2_P3_P4_P5_P6_P7
	int i;
	char v[40];
	char *av[10];
	int portbits;
	int mval[8];

	nvram_get_r_def("x_QOS_RM_DSCP", v, sizeof(v), "00_0_0_0_0_46_46_46_46");
	if (sep_str(v, av, sizeof(av) / sizeof(char *), "_") == 9) {
		portbits = strtoul(av[0], NULL, 16);
		for (i = 0; i < 8; i++)
			mval[i] = atoi(av[i + 1]);
		qos_port_remark(portbits, "dscp", mval);
	} else {
		fprintf(stderr, "error %s, check value!!!\n", "QOS_RM_DSCP");
	}
	nvram_get_r_def("x_QOS_RM_1Q", v, sizeof(v), "00_0_1_2_3_4_5_6_7");
	if (sep_str(v, av, sizeof(av) / sizeof(char *), "_") == 9) {
		portbits = strtoul(av[0], NULL, 16);
		for (i = 0; i < 8; i++)
			mval[i] = atoi(av[i + 1]);
		qos_port_remark(portbits, "1q", mval);
	} else {
		fprintf(stderr, "error %s, check value!!!\n", "QOS_RM_1Q");
	}
}

static void ip2str(char *ipstr, unsigned int ip)
{
	struct in_addr a;

	a.s_addr = htonl(ip);
	strcpy(ipstr, inet_ntoa(a));
}

static void get_ip_mask(char *ipstr, char *maskstr, unsigned int *ip, unsigned int *mask)
{
	*ip = *mask = 0;
	if (ipstr[0])
		*ip = strtoul(ipstr, NULL, 16);
	if (maskstr[0])
		*mask = ((unsigned int)0xffffffff) << (32 - atoi(maskstr));
	if ((*ip) & !(*mask))
		*mask = 0xffffffff;
}

static int get_port_range(char *pstr0, char *pstr1, unsigned short *p0, unsigned short *p1)
{
	*p0 = *p1 = 0;
	if (pstr0[0])
		*p0 = atoi(pstr0);
	if (pstr1[0])
		*p1 = atoi(pstr1);

	if (((*p0) == 0) && ((*p1) == 0)) {
		*p0 = 0;
		*p1 = 65535;
		return 0;
	}
	if (*p0 > *p1) {
		*p1 = *p0;
	}
	return 1;
}

static void handle_rule_0(char *cmd, char *av[])
{
	/*
	   0 1    2  3   4    5   6    7      8      9   (10)
	   QOS_R_# 0_intf_P#_VID_VPRI_SIP_SIPM_SPORT0_SPORT1_ACT
	 */
	int phy;
	unsigned short vlan, vlanm;
	unsigned int ip, ipm;
	unsigned short portL, portU;
	int n;
	int layer = 0;
	int act;

	cmd[0] = 0;
	ip = ipm = 0;
	vlan = vlanm = portL = portU = 0;
	phy = -1;

	if (av[2][0])
		phy = 0x01 << atoi(av[2]);

	if (av[3][0]) {
		vlan |= atoi(av[3]);
		vlanm |= 0x0fff;
	}
	if (av[4][0]) {
		vlan |= ((atoi(av[4]) << 13) & 0xe000);
		vlanm |= 0xe000;
	}
	get_ip_mask(av[5], av[6], &ip, &ipm);

	if (get_port_range(av[7], av[8], &portL, &portU))
		layer = 4;

	if ((layer == 0) && ip) {
		layer = 3;
	}

	if (av[9][0] == 'd')
		act = 8;
	else
		act = atoi(av[9]);

	n = sprintf(cmd, "aclwrite add %s -d in -q -r sfilter -o 7", av[1]);
	if (phy != -1)
		n += sprintf(&cmd[n], " -P 0x%x/0xff", phy);
	if (vlanm)
		n += sprintf(&cmd[n], " -v 0x%x/0x%x", vlan, vlanm);

	if (ip) {
		char ipstr[20], mstr[20];

		ip2str(ipstr, ip);
		ip2str(mstr, ipm);
		n += sprintf(&cmd[n], " -i %s/%s", ipstr, mstr);
	}
	n += sprintf(&cmd[n], " -p %u:%u", portL, portU);
	if (layer == 3) {
		n += sprintf(&cmd[n], " -4");
	} else if (layer == 0) {
		n += sprintf(&cmd[n], " -3");
	}
	if (act == 8) {
		n += sprintf(&cmd[n], " -a drop");
	} else {
		n += sprintf(&cmd[n], " -a prio -y %d", act);
	}
}

static void handle_rule_1(char *cmd, char *av[])
{
	/*
	   0 1    2   3    4   5    6      7      8      (9)
	   QOS_R_# 1_intf_VID_VPRI_DIP_DIPM_DPORT0_DPORT1_ACT
	 */
	unsigned short vlan, vlanm;
	unsigned int ip, ipm;
	unsigned short portL, portU;
	int n;
	int layer = 0;
	int act;

	cmd[0] = 0;
	ip = ipm = 0;
	vlan = vlanm = portL = portU = 0;

	if (av[2][0]) {
		vlan |= atoi(av[2]);
		vlanm |= 0x0fff;
	}
	if (av[3][0]) {
		vlan |= ((atoi(av[3]) << 13) & 0xe000);
		vlanm |= 0xe000;
	}
	get_ip_mask(av[4], av[5], &ip, &ipm);

	if (get_port_range(av[6], av[7], &portL, &portU))
		layer = 4;

	if ((layer == 0) && ip) {
		layer = 3;
	}

	if (av[8][0] == 'd')
		act = 8;
	else
		act = atoi(av[8]);

	n = sprintf(cmd, "aclwrite add %s -d in -q -r dfilter -o 7", av[1]);
	if (vlanm)
		n += sprintf(&cmd[n], " -v 0x%x/0x%x", vlan, vlanm);

	if (ip) {
		char ipstr[20], mstr[20];

		ip2str(ipstr, ip);
		ip2str(mstr, ipm);
		n += sprintf(&cmd[n], " -i %s/%s", ipstr, mstr);
	}
	n += sprintf(&cmd[n], " -p %u:%u", portL, portU);
	if (layer == 3) {
		n += sprintf(&cmd[n], " -4");
	} else if (layer == 0) {
		n += sprintf(&cmd[n], " -3");
	}
	if (act == 8) {
		n += sprintf(&cmd[n], " -a drop");
	} else {
		n += sprintf(&cmd[n], " -a prio -y %d", act);
	}
}

static void handle_rule_2(char *cmd, char *av[])
{
	/*
	   0 1    2   3    4   5    6   7    8     9     (10)
	   QOS_R_# 2_intf_SIP_SIPM_DIP_DIPM_TOS_TOSM_PROTO_ACT
	 */
	unsigned int sip, sipm;
	unsigned int dip, dipm;
	unsigned short tos, tosm, proto;
	int n;
	int act;

	cmd[0] = 0;
	sip = sipm = 0;
	dip = dipm = 0;
	tos = tosm = proto = 0;

	get_ip_mask(av[2], av[3], &sip, &sipm);
	get_ip_mask(av[4], av[5], &dip, &dipm);

	if (av[6][0]) {
		tos = strtoul(av[6], NULL, 16);
		if (av[7][0]) {
			tosm = strtoul(av[7], NULL, 16);
		} else {
			tosm = 0xffff;
		}
	}
	if (av[8][0])
		proto = strtoul(av[8], NULL, 0);

	if (av[9][0] == 'd')
		act = 8;
	else
		act = atoi(av[9]);

	n = sprintf(cmd, "aclwrite add %s -d in -q -r ip -o 7", av[1]);

	if (sip) {
		char ipstr[20], mstr[20];

		ip2str(ipstr, sip);
		ip2str(mstr, sipm);
		n += sprintf(&cmd[n], " -i %s/%s", ipstr, mstr);
	} else {
		n += sprintf(&cmd[n], " -i any");
	}
	if (dip) {
		char ipstr[20], mstr[20];

		ip2str(ipstr, dip);
		ip2str(mstr, dipm);
		n += sprintf(&cmd[n], "_%s/%s", ipstr, mstr);
	}
	if (tosm) {
		n += sprintf(&cmd[n], " -t 0x%x/0x%x", tos, tosm);
	}
	if (proto) {
		n += sprintf(&cmd[n], " -T %d", proto);
	}

	if (act == 8) {
		n += sprintf(&cmd[n], " -a drop");
	} else {
		n += sprintf(&cmd[n], " -a prio -y %d", act);
	}
}

static void handle_rule_3(char *cmd, char *av[])
{
	/*
	   0 1    2   3    4   5    6   7    8  9      10     11     12     13   (14)
	   QOS_R_# 3_intf_SIP_SIPM_DIP_DIPM_TOS_TOSM_TU_SPORT0_SPORT1_DPORT0_DPORT1_ACT

	   a123456789b123456789c123456789d123456789e123456789f123456789g123456789h123456789
	   Q_R_00=3_eth0_abcdef01_24_abcdef01_24_00_00_T_00000_00000_00000_00000_d
	 */
	unsigned int sip, sipm;
	unsigned int dip, dipm;
	unsigned short tos, tosm;
	int n;
	int act;
	unsigned short sportL, sportU;
	unsigned short dportL, dportU;
	int is_tcp = 0;

	cmd[0] = 0;
	sip = sipm = 0;
	dip = dipm = 0;
	tos = tosm = 0;
	sportL = sportU = 0;
	dportL = dportU = 0;

	get_ip_mask(av[2], av[3], &sip, &sipm);
	get_ip_mask(av[4], av[5], &dip, &dipm);

	if (av[6][0]) {
		tos = strtoul(av[6], NULL, 16);
		if (av[7][0]) {
			tosm = strtoul(av[7], NULL, 16);
		} else {
			tosm = 0xffff;
		}
	}
	if (toupper(av[8][0]) == 'T')
		is_tcp = 1;
	else
		is_tcp = 0;

	get_port_range(av[9], av[10], &sportL, &sportU);
	get_port_range(av[11], av[12], &dportL, &dportU);

	if (toupper(av[13][0]) == 'D')
		act = 8;
	else
		act = atoi(av[13]);

	n = sprintf(cmd, "aclwrite add %s -d in -q -r %s -o 7", av[1], is_tcp ? "tcp" : "udp");

	if (sip) {
		char ipstr[20], mstr[20];

		ip2str(ipstr, sip);
		ip2str(mstr, sipm);
		n += sprintf(&cmd[n], " -i %s/%s", ipstr, mstr);
	} else {
		n += sprintf(&cmd[n], " -i any");
	}
	if (dip) {
		char ipstr[20], mstr[20];

		ip2str(ipstr, dip);
		ip2str(mstr, dipm);
		n += sprintf(&cmd[n], "_%s/%s", ipstr, mstr);
	}
	if (tosm) {
		n += sprintf(&cmd[n], " -t 0x%x/0x%x", tos, tosm);
	}

	if ((sportL == 0) && (sportU == 65535) && (dportL == 0) && (dportU == 65535)) {
		// no rule for port.
	} else {
		n += sprintf(&cmd[n], " -p %d:%d_%d:%d", sportL, sportU, dportL, dportU);
	}

	if (act == 8) {
		n += sprintf(&cmd[n], " -a drop");
	} else {
		n += sprintf(&cmd[n], " -a prio -y %d", act);
	}
}

static void handle_rule_4(char *cmd, char *av[])
{
	/*
	   0 1    2     (3)
	   QOS_R_# 4_INTF_VPRI_ACT
	   INTF is dummy.
	 */
	int pri, act;

	pri = atoi(av[2]);
	if (toupper(av[3][0]) == 'D')
		act = 8;
	else
		act = atoi(av[3]);

	if (((pri >= 0) && (pri <= 7))
		&& ((act >= 0) && (act <= 7))) {
		qos_1q_2_ipri(pri, act);
	} else {
		fprintf(stderr, "handle_rule_4():%d,%d ignored.\n", pri, act);
	}
}

static void handle_rule_5(char *cmd, char *av[])
{	
	unsigned char sip[80], dip[80];
	unsigned int sipm, dipm;
	unsigned short tc, tcm, proto;
	int n;
	int act;

	cmd[0] = 0;
	sip[0] = dip[0] = 0;
	sipm = dipm = 0;
	tc = tcm = proto = 0;

	if ( av[2][0] )
		sprintf(sip, "%s", av[2]);
	
	if ( av[3][0] )
		sipm = strtoul(av[3], NULL, 10);
	
	if ( av[4][0] )
		sprintf(dip, "%s", av[4]);
	
	if ( av[5][0] )
		dipm = strtoul(av[5], NULL, 10);

	if (av[6][0]) {
		tc = strtoul(av[6], NULL, 16);
		if (av[7][0]) {
			tcm = strtoul(av[7], NULL, 16);
		} else {
			tcm = 0xffff;
		}
	}
	if (av[8][0])
		proto = strtoul(av[8], NULL, 0);
		
	if (av[9][0] == 'd')
		act = 8;
	else
		act = atoi(av[9]);

	n = sprintf(cmd, "aclwrite add %s -d in -r ipv6 -o 7", av[1]);

	if (sip[0]) {
		n += sprintf(&cmd[n], " -i %s/%u", sip, sipm);
	} else {
		n += sprintf(&cmd[n], " -i any");
	}
	if (dip[0]) {
		n += sprintf(&cmd[n], "_%s/%u", dip, dipm);
	}
	if (tcm) {
		n += sprintf(&cmd[n], " -C 0x%x/0x%x", tc, tcm);
	}
	
	if (proto) {
		n += sprintf(&cmd[n], " -H %d", proto);
	}
	
	if (act == 8) {
		n += sprintf(&cmd[n], " -a drop");
	} else {
		n += sprintf(&cmd[n], " -a prio -y %d", act);
	}
}

void qos_rule_apply(void)
{
	int i;
	int max;
	char v[80];
	char cmd[256];
	char *av[15];
	int arg_num;

	yexecl(NULL,"aclwrite flush eth1 -q");
	yexecl(NULL,"aclwrite flush br0 -q");
	yexecl(NULL,"aclwrite flush eth1 -c -30000");
	yexecl(NULL,"aclwrite flush br0 -c -30000");

	qos_1q_2_ipri(-1, -1);

	nvram_get_r_def("x_Q_R_NUM", v, sizeof(v), "0");
	max = atoi(v);

	for (i = 0; i < max; i++) {
		sprintf(cmd, "x_Q_R_%d", i);
		nvram_get_r_def(cmd, v, sizeof(v), "");
		if (v[0] == '0')
			arg_num = 10;
		else if (v[0] == '1')
			arg_num = 9;
		else if (v[0] == '2')
			arg_num = 10;
		else if (v[0] == '3')
			arg_num = 14;
		else if (v[0] == '4')
			arg_num = 4;
		else if (v[0] == '5')
			arg_num = 11;
		else
			continue;

		if (sep_str(v, av, sizeof(av) / sizeof(char *), "_") != arg_num)
			continue;

		if (av[0][0] != '4' && av[1][0] == 0)	// intf is null, ignore rule
			continue;

		cmd[0] = 0;
		switch (av[0][0]) {
		case '0':
			handle_rule_0(cmd, av);
			break;
		case '1':
			handle_rule_1(cmd, av);
			break;
		case '2':
			handle_rule_2(cmd, av);
			break;
		case '3':
			handle_rule_3(cmd, av);
			break;
		case '4':
			handle_rule_4(cmd, av);
			break;
		case '5':
			handle_rule_5(cmd, av);
			break;
		default:
			continue;
		}
		if (cmd[0]) {
			if (verbose)
				printf("cmd:%s\n", cmd);
			yexecl(NULL, cmd);
		}
	}
	yexecl(NULL,"aclwrite add br0 -q -d in -a prio -r mac -y 0 -o 7");
}
