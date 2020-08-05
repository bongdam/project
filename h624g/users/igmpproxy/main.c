#if defined(__DAVO__)
#include <dvflag.h>
#include <brdio.h>
#include <libytool.h>
#endif
#include "mclab.h"
#include "timeout.h"
#include "igmpproxy.h"
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include "built_time"

struct igmp_timer	startupQueryTimer;
static struct igmp_timer	generalQueryTimer;
static struct igmp_timer	linkChangeQueryTimer;


#if defined(__DAVO__)
#define MAX_PORT 4
struct dv_igmp_limite {
	int limite[MAX_PORT+1];
	int current[MAX_PORT+1];
	int enabled;
};

# ifdef MEMBER_QUERY_INTERVAL
#  undef MEMBER_QUERY_INTERVAL
# endif
# ifdef PERIODICAL_GENERAL_QUERY_INTERVAL
#  undef PERIODICAL_GENERAL_QUERY_INTERVAL
# endif
# ifdef STARTUP_GENERAL_QUERY_INTERVAL
#  undef STARTUP_GENERAL_QUERY_INTERVAL
# endif

#define LINK_UP		1
#define LINK_DOWN 	0

static int init_timeout_value(void);
static void dv_igmp_limite_enabled(int enabled);
static void dv_igmp_limite_set(int port, int limite);
static int dv_igmp_limite_check(__u32 source, __u32 group);
static void igmp_specific_timer_expired2(void *arg);
static void send_specific_query_to_all(void *arg);
static int pidfile_acquire(char *name);
static void pidfile_write_release(int pid_fd);
static void pidfile_delete(char *name);
static void background(void);
static void br_setpid(void);
static const char *portname(int port);
static int locate_port(__u32 source, __u32 group, int *fwdmask);

static int bFastLeave = 1;
static u_long MEMBER_QUERY_INTERVAL = 180;
static u_long PERIODICAL_GENERAL_QUERY_INTERVAL = 125;
static u_long STARTUP_GENERAL_QUERY_INTERVAL = 5;
static u_long GENERAL_QUERY_MAX_RSP_TIME;
static int wanlink = LINK_UP;

static struct igmp_timer SpecificQueryTimer;
static struct dv_igmp_limite igmp_limite;
#endif

#if defined (CONFIG_QUERIER_SELECTION)
//#define CONFIG_QUERIER_SELECTION_DEBUG
static struct igmp_timer querierSelectionTimer;
static struct timeval preOtherQueryTime;
unsigned long otherQuerierQueryInterval=0;
unsigned int otherQuerierIP=0;

int rxIgmpFromDownStream=0;
int querierSelectionResult=QUERIER_IS_ME;

#define IFACE_FLAG_T 0x01
#define IP_ADDR_T 0x02
#define NET_MASK_T 0x04
#define HW_ADDR_T 0x08

#define BR_QUERIER_INFO "/proc/br_igmpQuerierInfo"
int initQuerierSelection(void)
{
	memset(&preOtherQueryTime, 0 ,sizeof(struct timeval ));
	querierSelectionResult=QUERIER_IS_ME;
}

int getInAddr( char *interface, int type, void *pAddr )
{
    struct ifreq ifr;
    int skfd, found=0;
	struct sockaddr_in *addr;
    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    strcpy(ifr.ifr_name, interface);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0){
    		close( skfd );
		return (0);
	}
    if (type == HW_ADDR_T) {
    	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) >= 0) {
		memcpy(pAddr, &ifr.ifr_hwaddr, sizeof(struct sockaddr));
		found = 1;
	}
    }
    else if (type == IP_ADDR_T) {
	if (ioctl(skfd, SIOCGIFADDR, &ifr) == 0) {
		addr = ((struct sockaddr_in *)&ifr.ifr_addr);
		*((struct in_addr *)pAddr) = *((struct in_addr *)&addr->sin_addr);
		found = 1;
	}
    }
    else if (type == NET_MASK_T) {
	if (ioctl(skfd, SIOCGIFNETMASK, &ifr) >= 0) {
		addr = ((struct sockaddr_in *)&ifr.ifr_addr);
		*((struct in_addr *)pAddr) = *((struct in_addr *)&addr->sin_addr);
		found = 1;
	}
    }else {

    	if (ioctl(skfd, SIOCGIFDSTADDR, &ifr) >= 0) {
		addr = ((struct sockaddr_in *)&ifr.ifr_addr);
		*((struct in_addr *)pAddr) = *((struct in_addr *)&addr->sin_addr);
		found = 1;
	}

    }
    close( skfd );
    return found;

}

int checkQuerierSelectionResult(void)
{

	return querierSelectionResult;
}

void querierSelectionTimerExpired(void *arg)
{
	struct igmp_timer	*timerPtr=arg;
	if(timerPtr!=NULL)
	{
		untimeout(&timerPtr->ch);
	}

	memset(&preOtherQueryTime, 0 ,sizeof(struct timeval ));
	querierSelectionResult=QUERIER_IS_ME;

#if defined (CONFIG_QUERIER_SELECTION_DEBUG)
	printf("it's my turn to send query\n");
#endif
#if defined(__DAVO__)
	igmp_query(ALL_SYSTEMS, 0, GENERAL_QUERY_MAX_RSP_TIME);
#else
	igmp_query(ALL_SYSTEMS, 0, 1);
#endif

	return;
}

int isQueryFromDownStream(char *ifName, unsigned int querierIp)
{

	FILE *fp=NULL;
	unsigned char tempBuf[256];
	char *strPtr;
	unsigned char *tokPtr;
	unsigned char tempIfName[32];
	unsigned int tempQuerierIp[4];
	unsigned long tempElapseTime;
	int ret=0;

	fp = fopen(BR_QUERIER_INFO,"r");
	if(fp==NULL)
	{
		return 0;
	}


	fread(tempBuf,1,sizeof(tempBuf),fp);
	strPtr=tempBuf;

	while((tokPtr = strsep(&strPtr,"\n"))!=NULL)
	{

		if(strlen(tokPtr)<8)
		{
			continue;
		}
		sscanf(tokPtr,"%s %d.%d.%d.%d %u\n",
			tempIfName,
			&(tempQuerierIp[0]),
			&(tempQuerierIp[1]),
			&(tempQuerierIp[2]),
			&(tempQuerierIp[3]),
			&tempElapseTime);

#if defined (CONFIG_QUERIER_SELECTION_DEBUG)
		//printf("tempIfName is %s, %d.%d.%d.%d,tempElapseTime is %u\n",tempIfName,tempQuerierIp[0],tempQuerierIp[1],tempQuerierIp[2],tempQuerierIp[3],tempElapseTime);
#endif
		if((tempQuerierIp[0] == ((querierIp>>24)&0xFF))&&
			(tempQuerierIp[1] == ((querierIp>>16)&0xFF))&&
			(tempQuerierIp[2] == ((querierIp>>8)&0xFF))&&
			(tempQuerierIp[3] == (querierIp&0xFF) ))
		{
			if(strcmp(ifName,tempIfName)==0)
			{
				if(tempElapseTime<30)
				{
					ret=1;
				}
			}

		}
	}
out:
	fclose(fp);

	return ret;
}


int querierSelection(char *ifName, struct iphdr *ip, struct igmphdr *igmp)
{

	struct in_addr downIfIpAddr;
	unsigned long downStreamIp;

	unsigned int otherQuerierIp;
	int ret=0;


	if(isQueryFromDownStream(igmp_down_if_name, ip->saddr)==0)
	{
		return -1;
	}

	ret=getInAddr(ifName,IP_ADDR_T,(void *)&downIfIpAddr);

	if(ret==0)
	{
		return -1;
	}

	downStreamIp = *((unsigned long *)&downIfIpAddr);

	otherQuerierIp = ip->saddr;

	if(downStreamIp<otherQuerierIp)
	{


		if((preOtherQueryTime.tv_sec !=0) || (preOtherQueryTime.tv_usec !=0))
		{
			/*receive other querier's query,wait for it leave or expired*/
		}
		else
		{
			querierSelectionResult=QUERIER_IS_ME;
		}
	}
	else
	{

		otherQuerierIP=otherQuerierIp;

		gettimeofday(&preOtherQueryTime, NULL);
		querierSelectionResult=QUERIER_IS_OTHER;

		untimeout(&querierSelectionTimer.ch);
		otherQuerierQueryInterval=DEFAULT_OTHER_QUERIER_PRESENT_INTERVAL;
		querierSelectionTimer.type=0;
		querierSelectionTimer.retry_left=0;
		querierSelectionTimer.timerInterval=DEFAULT_OTHER_QUERIER_PRESENT_INTERVAL;
		timeout(querierSelectionTimerExpired , &querierSelectionTimer,	querierSelectionTimer.timerInterval, &querierSelectionTimer.ch);

	}


}
#endif


int igmp_query(__u32 dst, __u32 grp,__u8 mrt);

#define IGMP_MCAST2UNI
#ifdef	IGMP_MCAST2UNI
static void Update_igmpProxyStateToKernel(int igmpProxyEnable)
{
	//printf("\nUpdate_igmpProxyStateToKernel()\n");
	char *br_igmpProxy_Proc = "/proc/br_igmpProxy";
	char valueBeWirte[2]="01";
	FILE *fp = fopen(br_igmpProxy_Proc, "r+");
	int success;
	if (!fp) {
		printf("igmpProxy-error:Open %s file error.\n", br_igmpProxy_Proc);
		return;
	}

	if(igmpProxyEnable==1){
		success = fputc('1', fp);
	}else{
		success = fputc('0', fp);
	}
	if(success==EOF)
		printf("igmpProxy-error:Update_igmpProxyState fail.\n");

	fclose(fp);

}
#endif
struct igmp_timer qtimer;
// Kaohj -- toggle IGMP rx
int IGMP_rx_enable=0;
void igmp_timer_expired(void *arg);
void igmp_general_query_timer_expired(void *arg);
void igmp_specific_timer_expired(void *arg);
#if 0
static void pkt_debug(const char *buf)
{
int num2print = 20;
int i = 0;
	if(buf[0]==0x46)
		num2print = 24;
	for (i = 0; i < num2print; i++) {
		printf("%2.2x ", 0xff & buf[i]);
	}
	printf("\n");
	num2print = buf[3];
	for (; i < num2print; i++) {
		printf("%2.2x ", 0xff & buf[i]);
	}
	printf("\n");
}
#else
#define pkt_debug(buf)	do {} while (0)
#endif


static int  igmp_id = 0;

char igmp_down_if_name[IFNAMSIZ];
char igmp_down_if_idx;
#ifdef CONFIG_IGMPPROXY_MULTIWAN
char igmp_up_if_name[MAXWAN][IFNAMSIZ];
#else
char igmp_up_if_name[IFNAMSIZ];
#endif

#ifdef CONFIG_IGMPPROXY_MULTIWAN
char igmp_up_if_idx[MAXWAN];
#else
char igmp_up_if_idx;
#endif
#ifdef CONFIG_IGMPPROXY_MULTIWAN
int igmp_up_if_num;
#endif


#ifdef USE_STATIC_ENTRY_BUFFER
struct mcft_entry_en {
	int valid;
	struct mcft_entry entry_mcft_;
};

struct mbr_entry_en {
	int valid;
	struct mbr_entry entry_mbr_;
};
struct mcft_entry_en mcft_entry_tbl[MAX_MFCT_ENTRY];
struct mbr_entry_en mbr_entry_tbl[MAX_MBR_ENTRY];
#endif

#ifdef CONFIG_CHECK_MULTICASTROUTE
static int check_kernel_multicast_route(int entry)
{
	char buff[1024], iface[16];
	char net_addr[128], gate_addr[128], mask_addr[128];
	int num, iflags, refcnt, use, metric, mss, window, irtt;
	FILE *fp = fopen(routefile, "r");
	char *fmt;
	int found = 0;

	if (!fp) {
		printf("Open %s file error.\n", routefile);
		return;
	}

	fmt = "%16s %128s %128s %X %d %d %d %128s %d %d %d";

	while (fgets(buff, 1023, fp)) {
		num = sscanf(buff, fmt, iface, net_addr, gate_addr,
			&iflags, &refcnt, &use, &metric, mask_addr, &mss, &window, &irtt);
		if(entry ==1){
			if (num < 10 || (iflags !=0x1) || strcmp(iface, "br0")){
				continue;
			}
		}else if(entry == 2){
			if (num < 10 || (iflags != 0x5)  || strcmp(iface, "br0")){
			continue;
			}
		}
		if(entry ==1){
			 if (!strcmp(net_addr, "E0000000")) {
				 found = 1;
				 break;
			 }
		 }
		if(entry ==2){
			 if(!strcmp(net_addr, "FFFFFFFF")) {
				found = 2;
				break;
			}
		}
	}

	fclose(fp);
	return found;
}
#endif



struct mcft_entry *mcpq = NULL;

#ifdef USE_STATIC_ENTRY_BUFFER
struct mcft_entry * find_mcft_entry_from_tbl(void)
{
	int i;
	struct mcft_entry_en *valid_entry;

	for(i=0;i<MAX_MFCT_ENTRY;i++){
		valid_entry = &mcft_entry_tbl[i];
		if(valid_entry->valid==0){
			valid_entry->valid=1;
			return (&(valid_entry->entry_mcft_));
		}
	}
	//printf("find_mcft_entry_from_tbl fail\n");
	return 0;
}

int del_mcft_entry_from_tbl(struct mcft_entry *del_mcft_entry)
{

	int i;
	struct mcft_entry_en *valid_entry;
	struct mcft_entry *check_entry;
	for(i=0;i<MAX_MFCT_ENTRY;i++){
		valid_entry = &mcft_entry_tbl[i];
		check_entry = &(valid_entry->entry_mcft_);
		if(&(valid_entry->entry_mcft_)==del_mcft_entry){
			//printf("delmcft entry:group=%08X\n",check_entry->grp_addr);
			valid_entry->valid=0;
			return 1;
		}
	}
	//printf("del_mcft_entry_from_tbl fail\n");
	return 0;

}


struct mbr_entry * find_mbr_entry_from_tbl(void)
{
	int i;
	struct mbr_entry_en *valid_entry;

	for(i=0;i<MAX_MBR_ENTRY;i++){
		valid_entry = &mbr_entry_tbl[i];
		if(valid_entry->valid==0){
			valid_entry->valid=1;
			return (&(valid_entry->entry_mbr_));
		}
	}
	//printf("find_mbr_entry_from_tbl fail\n");
	return 0;
}

int del_mbr_entry_from_tbl(struct mbr_entry *del_mbr_entry)
{
	int i;
	struct mbr_entry_en *valid_entry;
	struct mbr_entry *check_entry;
	for(i=0;i<MAX_MBR_ENTRY;i++){
		valid_entry = &mbr_entry_tbl[i];
		check_entry = &(valid_entry->entry_mbr_);
		if(&(valid_entry->entry_mbr_)==del_mbr_entry){
			//printf("del mbr entry:user_addr=%08X\n",check_entry->user_addr);
			valid_entry->valid=0;
			return 1;
		}
	}
	//printf("del_mbr_entry_from_tbl fail\n");
	return 0;
}

#endif
struct mcft_entry * add_mcft(__u32 grp_addr, __u32 src_addr)
{
struct mcft_entry *mcp;
#ifdef KEEP_GROUP_MEMBER
	struct mbr_entry *gcp;
#endif
#ifndef USE_STATIC_ENTRY_BUFFER

	mcp = malloc(sizeof(struct mcft_entry));
	if(!mcp)
		return 0;
#ifdef KEEP_GROUP_MEMBER
	gcp = malloc(sizeof(struct mbr_entry));
	if (!gcp) {
		free(mcp);
		return 0;
	}
#endif

#else//static buffer
	mcp =find_mcft_entry_from_tbl();
	if(!mcp){
		return 0;
	}
#ifdef KEEP_GROUP_MEMBER
	gcp = find_mbr_entry_from_tbl();
	if (!gcp) {
		return 0;
	}
#endif

#endif
	mcp->grp_addr = grp_addr;
	// Kaohj -- add the first member
#ifdef KEEP_GROUP_MEMBER
	mcp->user_count = 1;
	gcp->user_addr = src_addr;
	gcp->port = locate_port(src_addr, grp_addr, NULL);
	gcp->next = NULL;
	mcp->grp_mbr = gcp;
#endif

#ifdef CONFIG_IGMPV3_SUPPORT
	mcp->igmp_ver = IGMP_VER_3;
	mcp->filter_mode = MCAST_INCLUDE;
	mcp->srclist = NULL;
	mcp->timer.lefttime = LAST_MEMBER_QUERY_INTERVAL;
	mcp->timer.retry_left = LAST_MEMBER_QUERY_COUNT;
	mcp->mrt_state = 0;
#endif /*CONFIG_IGMPV3_SUPPORT*/

	mcp->next = mcpq;
	mcpq = mcp;
	//return 0;
	return mcp;
}

// Kaohj --- add group timer for IGMP group-specific query.
int add_mcft_timer(__u32 grp_addr)
{
	struct mcft_entry **q, *p;

	/* Remove the entry from the  list. */
	for (p = mcpq; p!=0; p = p->next) {
		if(p->grp_addr == grp_addr) {
#ifdef PERIODICAL_SPECIFIC_QUERY
			p->timer.retry_left = MEMBER_QUERY_COUNT+1;
			timeout(igmp_specific_timer_expired , p, MEMBER_QUERY_INTERVAL, &p->timer.ch);
#endif
			return 0;
		}
	}
	return -1;
}
int del_mcft(__u32 grp_addr)
{
struct mcft_entry **q, *p;
#ifdef KEEP_GROUP_MEMBER
	struct mbr_entry *gt, *gc;
#endif


	/* Remove the entry from the  list. */
	for (q = &mcpq; (p = *q); q = &p->next) {
		if(p->grp_addr == grp_addr) {
			*q = p->next;
			// Kaohj -- free member list
#ifndef USE_STATIC_ENTRY_BUFFER
#ifdef KEEP_GROUP_MEMBER
			gc = p->grp_mbr;
			while (gc) {
				gt = gc->next;
				free(gc);
				gc = gt;
			}
#endif
#ifdef CONFIG_IGMPV3_SUPPORT
			{
			  struct src_entry *s, *sn;
			  s=p->srclist;
			  while(s)
			  {
			  	sn=s->next;
			  	free(s);
			  	s=sn;
			  }
			}
#endif
			untimeout(&p->timer.ch);
			free(p);
			return 0;
#else//static buffer

#ifdef KEEP_GROUP_MEMBER
			gc = p->grp_mbr;
			while (gc) {
				gt = gc->next;
				//printf("del mcft user=%08X\n",gc->user_addr);
				del_mbr_entry_from_tbl(gc);
				gc = gt;
			}
#endif

#ifdef CONFIG_IGMPV3_SUPPORT
			{
			  struct src_entry *s, *sn;
			  s=p->srclist;
			  while(s)
			  {
			  	sn=s->next;
			  	free(s);
			  	s=sn;
			  }
			}
#endif
			untimeout(&p->timer.ch);
			//printf("del mcft group=%08X\n",p->grp_addr);
			del_mcft_entry_from_tbl(p);

			return 0;
#endif
		}
	}
	return -1;
}

// Kaohj --- delete group timer for IGMP group-specific query.
int del_mcft_timer(__u32 grp_addr)
{
	struct mcft_entry *p;

	/* Remove the entry from the  list. */
	for (p = mcpq; p!=0; p = p->next) {
		if(p->grp_addr == grp_addr) {
			untimeout(&p->timer.ch);
			return 0;
		}
	}
	return -1;
}

int chk_mcft(__u32 grp_addr)
{
struct mcft_entry *mcp = mcpq;
	while(mcp) {
		if(mcp->grp_addr == grp_addr)
			return 1;
		mcp = mcp->next;
	}
	return 0;
}

struct mcft_entry * get_mcft(__u32 grp_addr)
{
struct mcft_entry *mcp = mcpq;
	while(mcp) {
		if(mcp->grp_addr == grp_addr)
			return mcp;
		mcp = mcp->next;
	}
	return NULL;
}

int num_mcft(void)
{
struct mcft_entry *mcp = mcpq;
int n = 0;
	while(mcp) {
		n++;
		mcp = mcp->next;
	}
	return n;
}

#ifdef KEEP_GROUP_MEMBER
// Kaohj -- attach user to group member list
//	0: fail
//	1: duplicate user
//	2: added successfully
int add_user(struct mcft_entry *mcp, __u32 src)
{
	struct mbr_entry *gcp;

	// check user
	gcp = mcp->grp_mbr;
	while (gcp) {
		if (gcp->user_addr == src)
			return 1;	// user exists
		gcp = gcp->next;
	}
#ifndef USE_STATIC_ENTRY_BUFFER
	// add user
	gcp = malloc(sizeof(struct mbr_entry));
#else
	gcp = find_mbr_entry_from_tbl();
#endif
	if (!gcp) {
		return 0;
	}
	gcp->user_addr = src;
	gcp->port = locate_port(src, mcp->grp_addr, NULL);
	gcp->next = mcp->grp_mbr;
	mcp->grp_mbr = gcp;
	mcp->user_count++;
	return 2;		//return value:added successfully
}

// Kaohj -- remove user from group member list
// return: user count
int del_user(struct mcft_entry *mcp, __u32 src)
{
	struct mbr_entry **q, *p;

	/* Remove the entry from the  list. */
	q = &mcp->grp_mbr;
	p = *q;
	while (p) {
		if(p->user_addr == src) {
			*q = p->next;
#ifndef USE_STATIC_ENTRY_BUFFER
			free(p);
#else
			del_mbr_entry_from_tbl(p);
#endif
			mcp->user_count--;
			return mcp->user_count;
		}
		q = &p->next;
		p = p->next;
	}

	return mcp->user_count;
}
#endif

/*
 * u_short in_cksum(u_short *addr, int len)
 *
 * Compute the inet checksum
 */
unsigned short in_cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    answer = ~sum;
    return (answer);
}

fd_set in_fds;		/* set of fds that wait_input waits for */
int max_in_fd;		/* highest fd set in in_fds */

/*
 * add_fd - add an fd to the set that wait_input waits for.
 */
void add_fd(int fd)
{
    FD_SET(fd, &in_fds);
    if (fd > max_in_fd)
	max_in_fd = fd;
}

/*
 * remove_fd - remove an fd from the set that wait_input waits for.
 */
void remove_fd(int fd)
{
    FD_CLR(fd, &in_fds);
}

/////////////////////////////////////////////////////////////////////////////
//	22/04/2004, Casey
/*
	Modified the following items:
	1.	delete all muticast router functions, xDSL router never use such function
	2.	igmp_handler only accept message for IGMP PROXY
	3.	IGMP proxy keep track on multicast address by mcft table,
		not multicast router module.

	igmp_handler rule:
	1.	only accept IGMP query from upstream interface, and it trigger
		downstream interface to send IGMP query.
	2.	only accept IGMP report from downstream interface, and it trigger
		upstream interface to send IGMP report.
	3.	when received IGMP report, recorded its group address as forwarding rule.
	4.	only accept IGMP leave from downstream interface, downstream interface
		will send IGMP general query twice to make sure there is no other member.
		If it cannot find any member, upstream interface will send IGMP leave.

	forwarding rule:
	1.	system only forward multicast packets from upstream interface to downstream interface.
	2.	system only forward multicast packets which group address learned by IGMP report.

*/
/////////////////////////////////////////////////////////////////////////////
//



#define RECV_BUF_SIZE	2048
char *recv_buf, *send_buf;
int igmp_socket;	/* down */
int igmp_socket2;	/* up */

int igmp_inf_create(char *ifname)
{
	struct ip_mreq mreq;
	int i;
	int ret;
	struct IfDesc *dp;
#if defined(__DAVO__)
	int tos;
	char dscp[16];
#endif

	dp = getIfByName(ifname);
	if(dp==NULL)
		return 0;

    if ((dp->sock = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP)) < 0)
		log(LOG_ERR, errno, "IGMP socket");
#if defined(__DAVO__)
	/*  +-+-+-+-+-+-+-+-+
	    |C|CLS| Option  | TYPE 8bits C=1 Option=20
	    +-+-+-+-+-+-+-+-+
	    Alert Value=0 (router shall examine packet)
	 */
	setsockopt(dp->sock, IPPROTO_IP, IP_OPTIONS, "\x94\x04\x00\x00", 4);
#else
	{
		/* Set router alert option*/
		char ra[4];
		ra[0] = 148;
		ra[1] = 4;
		ra[2] = 0;
		ra[3] = 0;
		setsockopt(dp->sock, IPPROTO_IP, IP_OPTIONS, ra, 4);
	}
#endif
	/* init igmp */
	/* Set reuseaddr, ttl, loopback and set outgoing interface */
	i = 1;
	ret = setsockopt(dp->sock, SOL_SOCKET, SO_REUSEADDR, (void*)&i, sizeof(i));
	if(ret)
		printf("setsockopt SO_REUSEADDR error!\n");
	i = 1;
	ret = setsockopt(dp->sock, IPPROTO_IP, IP_MULTICAST_TTL,
		(void*)&i, sizeof(i));
	if(ret)
		printf("setsockopt IP_MULTICAST_TTL error!\n");
	//eddie disable LOOP
	i = 0;
	if ( (ret = setsockopt(dp->sock, IPPROTO_IP, IP_MULTICAST_LOOP, (void*)&i, sizeof(i))) )
		printf("setsockopt IP_MULTICAST_LOOP error!\n");

	if ( (ret = setsockopt(dp->sock, IPPROTO_IP, IP_MULTICAST_IF, (void*)&dp->InAdr, sizeof(struct in_addr))) )
		printf("setsockopt IP_MULTICAST_IF error!\n");

	/* In linux use IP_PKTINFO */
	//IP_RECVIF returns the interface of received datagram
	i = 1;
	if ( (ret = setsockopt(dp->sock, IPPROTO_IP, IP_PKTINFO, &i, sizeof(i))) )
		printf("setsockopt IP_PKTINFO error!\n");

#if defined(__DAVO__)
	nvram_get_r_def("x_igmp_query_dscp", dscp, sizeof(dscp), "46");
	tos = (strtoul(dscp, NULL, 0) << 2) & 0xff;
	if (tos)
        	setsockopt(dp->sock, IPPROTO_IP, IP_TOS, (void *)&tos, sizeof(tos));
#endif
	//ret = fcntl(dp->sock, F_SETFL, O_NONBLOCK);
	//if(ret)
	//	printf("fcntl O_NONBLOCK error!\n");
	#if 0
	if (setsockopt(dp->sock, SOL_SOCKET, SO_BINDTODEVICE, ifname,strlen(ifname) + 1) == -1)
	{
		printf("bind to %s error", ifname);
	}
	#endif
	return 0;

}

int init_igmp(void)
{
	int val;
	recv_buf = malloc(RECV_BUF_SIZE);
	send_buf = malloc(RECV_BUF_SIZE);

	FD_ZERO(&in_fds);
	max_in_fd = 0;

	igmp_inf_create(igmp_down_if_name);

#ifdef CONFIG_IGMPPROXY_MULTIWAN
	int idx;
	for(idx=0;idx<igmp_up_if_num;idx++)
		igmp_inf_create(igmp_up_if_name[idx]);

#else
	igmp_inf_create(igmp_up_if_name);
#endif

	/*arrange start up query*/
	startupQueryTimer.type=LIMIT_RETRY_TIMER_TYPE;
	startupQueryTimer.retry_left=2;
	startupQueryTimer.timerInterval=STARTUP_GENERAL_QUERY_INTERVAL;
	timeout(igmp_general_query_timer_expired , &startupQueryTimer, startupQueryTimer.timerInterval, &startupQueryTimer.ch);

	/*schedule periodical general query*/
	generalQueryTimer.type=PERIODICAL_TIMER_TPYE;
	generalQueryTimer.retry_left=0xFFFFFFFF;
	generalQueryTimer.timerInterval=PERIODICAL_GENERAL_QUERY_INTERVAL;
	timeout(igmp_general_query_timer_expired , &generalQueryTimer,  generalQueryTimer.timerInterval, &generalQueryTimer.ch);

	// Kaohj --- enable IGMP rx
	IGMP_rx_enable = 1;
	return 0;
}

void shut_igmp_proxy(void)
{
	/* all interface leave multicast group */
}

#ifdef CONFIG_IGMPPROXY_MULTIWAN
// Kaohj -- add multicast membership to upstream interface(s)
int add_membership(__u32 group)
{
struct ip_mreq mreq;
struct IfDesc *up_dp ;
int index;
int ret;

	for(index=0;index<igmp_up_if_num;index++)
	{
		up_dp= getIfByName(igmp_up_if_name[index]);

		if(up_dp==NULL)
			continue;

		/* join multicast group */
		mreq.imr_multiaddr.s_addr = group;
		mreq.imr_interface.s_addr = up_dp->InAdr.s_addr;
		ret = setsockopt(up_dp->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*)&mreq, sizeof(mreq));
		if(ret) {
			fprintf(stderr,"setsockopt IP_ADD_MEMBERSHIP %s error!\n", inet_ntoa(mreq.imr_multiaddr));
			return ret;
		}
	}
}

// Add MRoute
int add_mfc(__u32 group, __u32 src)
{
	struct MRouteDesc	mrd;
	int index;
	struct IfDesc *up_dp ;

	for(index=0;index<igmp_up_if_num;index++) {
		up_dp= getIfByName(igmp_up_if_name[index]);

		if(up_dp==NULL)
			continue;
		/* add multicast routing entry */
		//mrd.OriginAdr.s_addr = 0;
		mrd.OriginAdr.s_addr = mrd.InVif; //jjh checkcode#1
		// Kaohj --- special case, save the subscriber IP to kernel
		// in order to take the subscriber IP (source IP) to the upstream server
		mrd.SubsAdr.s_addr = src;
		mrd.McAdr.s_addr = group;
		mrd.InVif = igmp_up_if_idx[index];
		memset(mrd.TtlVc, 0, sizeof(mrd.TtlVc));
		mrd.TtlVc[igmp_down_if_idx] = 1;
		addMRoute(&mrd);
	}
	return 1;
}


// Kaohj -- delete multicast membership to upstream interface(s)
int del_membership(__u32 group)
{
struct ip_mreq mreq;
struct IfDesc *up_dp ;
int ret;
int index;

	for(index=0;index<igmp_up_if_num;index++){
		up_dp= getIfByName(igmp_up_if_name[index]);
		if(up_dp==NULL)
			continue;
		/* drop multicast group */
		mreq.imr_multiaddr.s_addr = group;
		mreq.imr_interface.s_addr = up_dp->InAdr.s_addr;
		if ( (ret = setsockopt(up_dp->sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (void*)&mreq, sizeof(mreq))) )
			printf("setsockopt IP_DROP_MEMBERSHIP %s error!\n", inet_ntoa(mreq.imr_multiaddr));
	}
}

// Delete MRoute
int del_mfc(__u32 group)
{
	struct MRouteDesc	mrd;
	int index;

	for(index=0;index<igmp_up_if_num;index++) {
		/* delete multicast routing entry */
		mrd.OriginAdr.s_addr = igmp_up_if_idx[index]; //jjh checkcode#1
		mrd.McAdr.s_addr = group;
		mrd.InVif = igmp_up_if_idx[index];
		memset(mrd.TtlVc, 0, sizeof(mrd.TtlVc));
		delMRoute(&mrd);
	}
	return 1;
}

#else

// Kaohj -- add multicast membership to upstream interface(s)
int add_membership(__u32 group)
{
#if defined(__DAVO__)
	struct ip_mreqn mreq;
#else
	struct ip_mreq mreq;
#endif
	struct IfDesc *up_dp = getIfByName(igmp_up_if_name);
	int res;

	/* join multicast group */
#if defined(__DAVO__)
	mreq.imr_multiaddr.s_addr = group;
	mreq.imr_address.s_addr = up_dp->InAdr.s_addr;
	mreq.imr_ifindex = up_dp->IfIndex;
#else
	mreq.imr_multiaddr.s_addr = group;
	mreq.imr_address.s_addr = up_dp->InAdr.s_addr;
#endif
	if ( (res = setsockopt(up_dp->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*)&mreq, sizeof(mreq))) ) {
		printf("setsockopt IP_ADD_MEMBERSHIP %s error!\n", inet_ntoa(mreq.imr_multiaddr));
		LOG(LOG_INFO, "IGMP failed IP_ADD_MEMBERSHIP %u.%u.%u.%u", NIPQUAD(group));
		return res;
	}
#if !defined(__DAVO__)
	syslog(LOG_INFO, "igmpproxy: Add membership %s", inet_ntoa(mreq.imr_multiaddr));
#endif
	return 1;
}

// Add MRoute
int add_mfc(__u32 group, __u32 src)
{
	struct MRouteDesc	mrd;

	/* add multicast routing entry */
	mrd.OriginAdr.s_addr =igmp_up_if_idx;//jjh checkcode#1
	//mrd.OriginAdr.s_addr = 0;
	// Kaohj --- special case, save the subscriber IP to kernel
	// in order to take the subscriber IP (source IP) to the upstream server
	mrd.SubsAdr.s_addr = src;
	mrd.McAdr.s_addr = group;
	mrd.InVif = igmp_up_if_idx;
	memset(mrd.TtlVc, 0, sizeof(mrd.TtlVc));
	mrd.TtlVc[igmp_down_if_idx] = 1;
	addMRoute(&mrd);
	return 1;
}


// Kaohj -- delete multicast membership to upstream interface(s)
int del_membership(__u32 group)
{
#if defined(__DAVO__)
	struct ip_mreqn mreq;
#else
	struct ip_mreq mreq;
#endif
	struct IfDesc *up_dp = getIfByName(igmp_up_if_name);
	int ret;

	/* drop multicast group */
#if defined(__DAVO__)
	mreq.imr_multiaddr.s_addr = group;
	mreq.imr_address.s_addr = up_dp->InAdr.s_addr;
	mreq.imr_ifindex = up_dp->IfIndex;
#else
	mreq.imr_multiaddr.s_addr = group;
	mreq.imr_interface.s_addr = up_dp->InAdr.s_addr;
	mreq.imr_ifindex = up_dp->IfIndex;
#endif
	if ( (ret = setsockopt(up_dp->sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (void*)&mreq, sizeof(mreq))) ) {
		printf("setsockopt IP_DROP_MEMBERSHIP %s error!\n", inet_ntoa(mreq.imr_multiaddr));
		LOG(LOG_INFO, "IGMP failed IP_DROP_MEMBERSHIP %u.%u.%u.%u", NIPQUAD(group));
	}
#if !defined(__DAVO__)
	syslog(LOG_INFO, "igmpproxy: Drop membership %s", inet_ntoa(mreq.imr_multiaddr));
#endif

	return 1;
}

// Delete MRoute
int del_mfc(__u32 group)
{
	struct MRouteDesc mrd;

	/* delete multicast routing entry */
	mrd.OriginAdr.s_addr = igmp_up_if_idx; //jjh checkcode#1
	mrd.McAdr.s_addr = group;
	mrd.InVif = igmp_up_if_idx;
	memset(mrd.TtlVc, 0, sizeof(mrd.TtlVc));
	delMRoute(&mrd);
	return 1;
}

#endif
// Add group membershipt and MRoute
int add_mr(__u32 group, __u32 src)
{
	add_membership(group);
	add_mfc(group, src);
	return 1;
}


// Delete group membership and MRoute
int del_mr(__u32 group)
{
	del_membership(group);
	del_mfc(group);
	return 1;
}

void igmp_specific_timer_expired2(void *arg)
{
	struct mcft_entry *mcp = arg;

	//printf("igmp_specific_timer_expired2()\n");
	if (!mcp)
		return;

	mcp->timer.retry_left--;

	if (mcp->timer.retry_left <= 0) {
		// Kaohj --- check if group has already been dropped
		untimeout(&mcp->timer.ch);
		if (strcmp(igmp_up_if_name, igmp_down_if_name) != 0) {
			del_mr(mcp->grp_addr);
		}
		del_mcft(mcp->grp_addr);
#if defined(__DAVO__)
		syslog(LOG_DEBUG, "IGMP SQTOUT2: delete group(%u.%u.%u.%u)", NIPQUAD(mcp->grp_addr));
#endif
	} else {
		timeout(igmp_specific_timer_expired2, mcp,
				LAST_MEMBER_QUERY_INTERVAL, &mcp->timer.ch);
		igmp_query(ALL_SYSTEMS, mcp->grp_addr, LAST_MEMBER_QUERY_INTERVAL);
	}
}

void igmp_specific_timer_expired(void *arg)
{
struct mcft_entry *mcp = arg;

	//printf("igmp_specific_timer_expired()\n");
	if(!mcp)
		return;

	mcp->timer.retry_left--;

	if(mcp->timer.retry_left <= 0) {
		// Kaohj --- check if group has already been dropped
#ifdef __DAVO__
		untimeout(&mcp->timer.ch);
#endif
#ifdef KEEP_GROUP_MEMBER
		if (mcp->user_count != 0) {
#endif
			del_mr(mcp->grp_addr);
			del_mcft(mcp->grp_addr);
#if defined(__DAVO__)
			syslog(LOG_DEBUG, "IGMP SQTOUT: delete group(%u.%u.%u.%u) uc(%d)",
						NIPQUAD(mcp->grp_addr), mcp->user_count);
#endif
#ifdef KEEP_GROUP_MEMBER
		}
#endif
#ifndef __DAVO__
		untimeout(&mcp->timer.ch);
#endif
	}
	else {
		timeout(igmp_specific_timer_expired , mcp, LAST_MEMBER_QUERY_INTERVAL, &mcp->timer.ch);
		igmp_query(ALL_SYSTEMS, mcp->grp_addr, LAST_MEMBER_QUERY_INTERVAL);
	}
}

void igmp_general_query_timer_expired(void *arg)
{
	struct igmp_timer	*timerPtr=arg;
	if(timerPtr!=NULL)
	{
		if((timerPtr->type==PERIODICAL_TIMER_TPYE))
		{
#if defined(__DAVO__)
			igmp_query(ALL_SYSTEMS, 0, GENERAL_QUERY_MAX_RSP_TIME);
#else
			igmp_query(ALL_SYSTEMS, 0, 1);
#endif

			timeout(igmp_general_query_timer_expired , timerPtr, timerPtr->timerInterval, &timerPtr->ch);
		}
		else
		{
			if(timerPtr->retry_left==0)
			{
				untimeout(&timerPtr->ch);
			}
			else
			{
#if defined(__DAVO__)
				igmp_query(ALL_SYSTEMS, 0, GENERAL_QUERY_MAX_RSP_TIME);
#else
				igmp_query(ALL_SYSTEMS, 0, 1);
#endif
				timerPtr->retry_left--;
				timeout(igmp_general_query_timer_expired , timerPtr, timerPtr->timerInterval, &timerPtr->ch);
			}
		}
	}
}

#ifdef CONFIG_CHECK_MULTICASTROUTE
int check_entry1=0;
int check_entry2=0;
int check_multicast_route=0;
#endif

int add_group_and_src( __u32 group, __u32 src )
{
	struct mcft_entry *mymcp;

	if(!IN_MULTICAST(group))
		return 0;
	/* check if it's protocol reserved group */
	if((group&0xFFFFFF00)==0xE0000000
#ifdef __DAVO__	/* 	APACRTL-536 */
	   || (group == __constant_htonl(0xE0000141))
	   || (group == __constant_htonl(0xE000014c))
	   || (group == __constant_htonl(0xE00001b2))
#endif
		)
		return 0;
	/* TBD */
	/* should check if it's from downtream interface */
#ifdef CONFIG_CHECK_MULTICASTROUTE
			if(check_multicast_route ==0){
				checkroute=check_kernel_multicast_route(1);
				if(checkroute ==1){
					system("route del -net 224.0.0.0 netmask 240.0.0.0 dev br0 2> /dev/null");
					check_entry1=1;
				}
				checkroute = 0;
				checkroute=check_kernel_multicast_route(2);
				if(checkroute ==2){
					system("route del -net 255.255.255.255 netmask 255.255.255.255 dev br0 2> /dev/null");
					check_entry2=1;
				}
				check_multicast_route = 1;
			}
#endif

	if(!chk_mcft(group)) {
		// Group does not exist on router, add multicast address into if_table
	//	struct IfDesc *up_dp = getIfByName(igmp_up_if_name);
		int ret;
		int tmp_port;
#if defined(__DAVO__)
		if (!dv_igmp_limite_check(src, group)) {
			LOG(LOG_INFO, "IGMP cant Join %u.%u.%u.%u from %u.%u.%u.%u(%s)[%d/%d]\n",
						NIPQUAD(group), NIPQUAD(src), portname((tmp_port=locate_port(src, group, NULL))),
						igmp_limite.current[tmp_port], igmp_limite.limite[tmp_port]);
			return 0;
		}
#endif
		mymcp = add_mcft(group, src);
		if(!mymcp) {
			//printf("igmp_accept> add group to list fail!\n");
			LOG(LOG_INFO, "IGMP reject Join %u.%u.%u.%u from %u.%u.%u.%u(%s)",
			    NIPQUAD(group), NIPQUAD(src), portname(locate_port(src, group, NULL)));
			return 0;
		}
		LOG(LOG_DEBUG, "IGMP %u.%u.%u.%u(%s) Joins %u.%u.%u.%u",
		    NIPQUAD(src), portname(locate_port(src, group, NULL)), NIPQUAD(group));
		// Kaohj
		//add_mr(group);
		add_mr(group, src);
#ifdef PERIODICAL_SPECIFIC_QUERY
		mymcp->timer.retry_left = MEMBER_QUERY_COUNT+1;
		timeout(igmp_specific_timer_expired , mymcp, MEMBER_QUERY_INTERVAL, &mymcp->timer.ch);
#endif
	}
	else {
		mymcp = get_mcft(group);
		if (mymcp) {
#ifndef __DAVO__
			untimeout(&mymcp->timer.ch);
#endif
#ifdef KEEP_GROUP_MEMBER
			if ( add_user(mymcp, src) == 2) {
				LOG(LOG_DEBUG, "IGMP %u.%u.%u.%u(%s) Joins %u.%u.%u.%u",
				    NIPQUAD(src), portname(locate_port(src, group, NULL)), NIPQUAD(group));
			}
#endif
#ifdef PERIODICAL_SPECIFIC_QUERY
#ifdef __DAVO__
			if (!timepending(&mymcp->timer.ch) ||
			    (mymcp->timer.retry_left < (MEMBER_QUERY_COUNT + 1))) {
			/* Reported by igmp_specific_timer_expired's being expired, NOT by general_query_timer */

				mymcp->timer.retry_left = MEMBER_QUERY_COUNT+1;
				timeout(igmp_specific_timer_expired , mymcp, MEMBER_QUERY_INTERVAL, &mymcp->timer.ch);
			}
#else
			mymcp->timer.retry_left = MEMBER_QUERY_COUNT + 1;
			timeout(igmp_specific_timer_expired, mymcp, MEMBER_QUERY_INTERVAL, &mymcp->timer.ch);
#endif
#endif
		}
	}


	return 0;
}

static char *get_portname(struct mcft_entry *mcp, __u32 src)
{
	struct mbr_entry **q, *p;
	int port = -1;

	q = &mcp->grp_mbr;
	p = *q;
	while (p) {
		if (p->user_addr == src) {
			port = p->port;
			return portname(port);
		}
		q = &p->next;
		p = p->next;
	}

	return portname(port);
}

int del_group_and_src( __u32 group, __u32 src )
{
	struct mcft_entry *mymcp;
	int query_count, query_interval;
#ifdef KEEP_GROUP_MEMBER
	int count;
#endif

	if(!IN_MULTICAST(group)) {
		//printf("igmp_accept> invalid multicast address or IGMP leave\n");
		LOG(LOG_DEBUG, "Could not delete group %u.%u.%u.%u", NIPQUAD(group));
		return 0;
	}
	//printf("igmp_accept> receive IGMP Leave from %s,", inet_ntoa(ip->saddr));
	//printf("group = %s\n", inet_ntoa(igmp->group));

	/* TBD */
	/* should check if it's from downtream interface */
	if(chk_mcft(group)) {
		mymcp = get_mcft(group);
		// Group does exist on router
		if(mymcp) {
			query_count = LAST_MEMBER_QUERY_COUNT;
			query_interval = LAST_MEMBER_QUERY_INTERVAL;

			LOG(LOG_DEBUG, "IGMP %u.%u.%u.%u(%s) %s Leaves %u.%u.%u.%u",
					NIPQUAD(src), get_portname(mymcp, src), ((bFastLeave)?"Fast": ""), NIPQUAD(group));
#ifdef KEEP_GROUP_MEMBER
			count = del_user(mymcp, src);

#if defined(__DAVO__)
			if (bFastLeave && count == 0) {	// no member, drop it!
				del_mr(mymcp->grp_addr);
				if (!del_mcft(mymcp->grp_addr))
					mymcp = NULL;
#ifdef CONFIG_CHECK_MULTICASTROUTE
				alarm(5);
#endif
			}
#else
			if (count == 0) {// no member, drop it!
				del_mr(mymcp->grp_addr);
				del_mcft(mymcp->grp_addr);
#ifdef CONFIG_CHECK_MULTICASTROUTE
				alarm(5);
#endif
			}
#endif

#endif
#if defined(__DAVO__)
			if (mymcp != NULL) {
				mymcp->timer.retry_left = LAST_MEMBER_QUERY_COUNT;
				timeout(igmp_specific_timer_expired2, mymcp, LAST_MEMBER_QUERY_INTERVAL, &mymcp->timer.ch);
			}
			igmp_query(ALL_SYSTEMS, group, LAST_MEMBER_QUERY_INTERVAL);
#else
			mymcp->timer.retry_left = LAST_MEMBER_QUERY_COUNT;
			timeout(igmp_specific_timer_expired , mymcp, LAST_MEMBER_QUERY_INTERVAL, &mymcp->timer.ch);
			igmp_query(ALL_SYSTEMS, mymcp->grp_addr, LAST_MEMBER_QUERY_INTERVAL);
#endif
		}
	}

	return 0;
}

/*
 * igmp_accept - handles the incoming IGMP packets
 *
 */

int igmp_accept(int recvlen, struct IfDesc *dp)
{
	register __u32 src, dst, group, group_src;
	struct iphdr *ip;
	struct igmphdr *igmp;
	int ipdatalen, iphdrlen, igmpdatalen;
	struct mcft_entry *mymcp;
#ifdef CONFIG_CHECK_MULTICASTROUTE
	int checkroute=0;
#endif
	struct igmpmsg *msg;
	if (recvlen < sizeof(struct iphdr)) {
		log(LOG_WARNING, 0,
		    "received packet too short (%u bytes) for IP header", recvlen);
		return 0;
	}

	ip  = (struct iphdr *)recv_buf;
	src = ip->saddr;
	dst = ip->daddr;

	if(!IN_MULTICAST(dst))	/* It isn't a multicast */
		return -1;
	if(chk_local(src)) 		/* It's our report looped back */
		return -1;
	if(dst == ALL_PRINTER)	/* It's MS-Windows UPNP all printers notify */
		return -1;
#if defined(__DAVO__)
	if ((ip->saddr & dp->InNetMask.s_addr) != (dp->InAdr.s_addr & dp->InNetMask.s_addr))
		return -1;
#endif
	pkt_debug(recv_buf);

	iphdrlen  = ip->ihl << 2;
	ipdatalen = ip->tot_len;

	igmp        = (struct igmphdr *)(recv_buf + iphdrlen);
	group   = igmp->group;

	/* determine message type */
	switch (igmp->type) {
		case IGMP_HOST_MEMBERSHIP_QUERY:
			/* Linux Kernel will process local member query, it won't reach here */
			#if 0
			// send General Query downstream
#if defined(__DAVO__)
			igmp_query(ALL_SYSTEMS, group, 10);
#else
			igmp_query(ALL_SYSTEMS, group, 1);
#endif
			#endif
			#if defined (CONFIG_QUERIER_SELECTION)
				querierSelection(dp->Name,ip,igmp);
			#endif
			break;

		case IGMP_HOST_MEMBERSHIP_REPORT:
#ifdef CONFIG_DEFAULTS_KERNEL_2_6
		case IGMPV2_HOST_MEMBERSHIP_REPORT:
#else
		case IGMP_HOST_NEW_MEMBERSHIP_REPORT:
#endif
			add_group_and_src(group,src);


			break;

		case IGMP_HOST_V3_MEMBERSHIP_REPORT:
			/* TBD */
			/* should check if it's from downtream interface */
#if 0
{
			group = *(__u32 *)((char *)igmp+12);
			//igmp_query(ALL_SYSTEMS, group, 1);
#if defined(__DAVO__)
			igmp_query(ALL_SYSTEMS, group, 10);
#else
			igmp_query(ALL_SYSTEMS, group, 1);
#endif
			break;
}
#else
{
			struct igmpv3_report *igmpv3;
			struct igmpv3_grec *igmpv3grec;
			unsigned short rec_id;

			igmpv3 = (struct igmpv3_report *)igmp;
			//printf( "recv IGMP_HOST_V3_MEMBERSHIP_REPORT\n" );
			//printf( "igmpv3->type:0x%x\n", igmpv3->type );
			//printf( "igmpv3->ngrec:0x%x\n", ntohs(igmpv3->ngrec) );

			rec_id=0;
			igmpv3grec =  &igmpv3->grec[0];
			while( rec_id < ntohs(igmpv3->ngrec) )
			{

				//printf( "igmpv3grec[%d]->grec_type:0x%x\n", rec_id, igmpv3grec->grec_type );
				//printf( "igmpv3grec[%d]->grec_auxwords:0x%x\n", rec_id, igmpv3grec->grec_auxwords );
				//printf( "igmpv3grec[%d]->grec_nsrcs:0x%x\n", rec_id, ntohs(igmpv3grec->grec_nsrcs) );
				//printf( "igmpv3grec[%d]->grec_mca:%s\n", rec_id, inet_ntoa(igmpv3grec->grec_mca) );

				group = igmpv3grec->grec_mca;

				switch( igmpv3grec->grec_type )
				{
					case IGMPV3_MODE_IS_INCLUDE:
					case IGMPV3_MODE_IS_EXCLUDE:
						if(chk_mcft(group))
						{
							//printf( "IS_IN or IN_EX\n" );
							add_group_and_src( group, src );
						}
						break;
					case IGMPV3_CHANGE_TO_INCLUDE:
						//printf( "TO_IN\n" );
						if( igmpv3grec->grec_nsrcs )
							add_group_and_src( group, src );
						else //empty
							del_group_and_src( group, src );
						break;
					case IGMPV3_CHANGE_TO_EXCLUDE:
						//printf( "TO_EX\n" );
						add_group_and_src( group, src );
						break;
					case IGMPV3_ALLOW_NEW_SOURCES:
						//printf( "ALLOW\n" );
						break;
					case IGMPV3_BLOCK_OLD_SOURCES:
						//printf( "BLOCK\n" );
						break;
					default:
						//printf( "!!! can't handle the group record types: %d\n", igmpv3grec->grec_type );
						break;
				}

				rec_id++;
				//printf( "count next: 0x%x %d %d %d %d\n", igmpv3grec, sizeof( struct igmpv3_grec ), igmpv3grec->grec_auxwords, ntohs(igmpv3grec->grec_nsrcs), sizeof( __u32 ) );
				igmpv3grec = (struct igmpv3_grec *)( (char*)igmpv3grec + sizeof( struct igmpv3_grec ) + (igmpv3grec->grec_auxwords+ntohs(igmpv3grec->grec_nsrcs))*sizeof( __u32 ) );
				//printf( "count result: 0x%x\n", igmpv3grec );
			}
			break;
}
#endif
			break;


		case IGMP_HOST_LEAVE_MESSAGE :
			del_group_and_src( group, src );

			break;
		// Kaohj
		case IGMPMSG_NOCACHE: // ipmr_cache_report (no route for incomming group)
			msg = (struct igmpmsg*)recv_buf;
			// The multicast stream may be dead, drop it!
			if (msg->im_vif != igmp_down_if_idx) // if not from downstream, send leave
				igmp_leave(dst, 0);
			break;
		default:
			//printf("igmp_accept> receive IGMP Unknown type [%x] from %s:", igmp->type, inet_ntoa(ip->saddr));
			//printf("%s\n", inet_ntoa(ip->daddr));
			break;
	}
	return 0;
}


/*
 * igmp_report - send an IGMP Report packet, directly to linkp->send(), not via ip
 *
 * int igmp_report( longword ina, int ifno )
 * Where:
 *	ina	the group address to report.
 *      ifno	interface number
 *
 * Returns:
 *	0	if unable to send report
 *	1	report was sent successfully
 */

int igmp_report(__u32 dst, int if_idx)
{
    struct iphdr *ip;
    struct igmphdr *igmp;
    struct sockaddr_in sdst;
    struct IfDesc *dp;
    int index;
	#ifdef CONFIG_IGMPPROXY_MULTIWAN
	int null_cnt=0;
	int err_cnt=0;
	#endif

	ip                      = (struct iphdr *)send_buf;
    ip->saddr       = getAddrByVifIx(if_idx);
    ip->daddr       = dst;
    ip->tot_len              = MIN_IP_HEADER_LEN + IGMP_MINLEN;
    if (IN_MULTICAST(ntohl(dst))) {
		ip->ttl = 1;
	#if 0
	/*
	    if (setsockopt(igmp_socket, IPPROTO_IP, IP_MULTICAST_IF,
		   	(char *)&ip->saddr, sizeof(struct in_addr)) < 0)
		   	printf("igmp_report> set multicast interface error\n");
	*/
	  if (setsockopt(dp->sock, IPPROTO_IP, IP_MULTICAST_IF,
		   	(char *)&ip->saddr, sizeof(struct in_addr)) < 0)
		   	printf("igmp_report> set multicast interface error\n");
	#endif

	}
    else
		ip->ttl = MAXTTL;

    igmp                    = (struct igmphdr *)(send_buf + MIN_IP_HEADER_LEN);
#ifdef CONFIG_DEFAULTS_KERNEL_2_6
    igmp->type         =IGMPV2_HOST_MEMBERSHIP_REPORT;
#else
    igmp->type         = IGMP_HOST_NEW_MEMBERSHIP_REPORT;
#endif
    igmp->code         = 0;
    igmp->group		   = dst;
    igmp->csum        = 0;
    igmp->csum        = in_cksum((u_short *)igmp, IGMP_MINLEN);

    bzero(&sdst, sizeof(sdst));
    sdst.sin_family = AF_INET;
    sdst.sin_addr.s_addr = dst;
#ifdef CONFIG_IGMPPROXY_MULTIWAN
	for(index=0;index<igmp_up_if_num;index++)
	{
		dp= getIfByName(igmp_up_if_name[index]);

		if(dp==NULL){
			null_cnt++;
			continue;
		}
		if (sendto(dp->sock, igmp,
			MIN_IP_HEADER_LEN + IGMP_MINLEN, 0,
			(struct sockaddr *)&sdst, sizeof(sdst)) < 0) {
			err_cnt++;
			printf("igmp_report> sendto error, from %s ", inet_ntoa(ip->saddr));
			printf("to %s\n", inet_ntoa(ip->daddr));
		}
	}
	//if getIfByName(up_if_name) failed every time
	if ((null_cnt>=igmp_up_if_num)||(err_cnt>=igmp_up_if_num))
		return 0;
#else
		// Kaohj
	dp = getIfByName(igmp_up_if_name);
	if (!dp)
		return 0;
	if (sendto(dp->sock, igmp,
			MIN_IP_HEADER_LEN + IGMP_MINLEN, 0,
			(struct sockaddr *)&sdst, sizeof(sdst)) < 0) {
		printf("igmp_report> sendto error, from %s ", inet_ntoa(ip->saddr));
		printf("to %s\n", inet_ntoa(ip->daddr));
		return 0;
	}
#endif

#if 0
    if (sendto(igmp_socket, send_buf,
			MIN_IP_HEADER_LEN + IGMP_MINLEN, 0,
			(struct sockaddr *)&sdst, sizeof(sdst)) < 0) {
		printf("igmp_report> sendto error, from %s ", inet_ntoa(ip->saddr));
		printf("to %s\n", inet_ntoa(ip->daddr));
    }
#endif
    return 1;
}




/*
 * igmp_query - send an IGMP Query packet to downstream interface
 *
 * int igmp_query(__u32 dst, __u32 grp,__u8 mrt)
 * Where:
 *  dst		destination address
 *  grp		query group address
 *  MRT		Max Response Time in IGMP header (in 1/10 second unit)
 *
 * Returns:
 *	0	if unable to send
 *	1	packet was sent successfully
 */

int igmp_query(__u32 dst, __u32 grp,__u8 mrt)
{
#if defined (CONFIG_IGMPV3_SUPPORT)
    struct igmpv3_query	*igmpv3;
#else
    struct igmphdr *igmp;
#endif
    struct sockaddr_in sdst;
    struct IfDesc *dp = getIfByName(igmp_down_if_name);
	char grp_addr[80];

#if defined (CONFIG_QUERIER_SELECTION)
	if(querierSelectionResult==QUERIER_IS_OTHER)
	{
		#if defined (CONFIG_QUERIER_SELECTION_DEBUG)
		printf("querier is %d.%d.%d.%d\n",
		(otherQuerierIP>>24)&0xFF,(otherQuerierIP)>>16&0xFF,(otherQuerierIP>>8)&0xFF,otherQuerierIP&0xFF);
		#endif
		return 0;
	}

	#if defined (CONFIG_QUERIER_SELECTION_DEBUG)
	printf("querier is me\n");
	#endif
#endif

	if(dp == NULL)
	{
		printf("get if(%s) failed\n",igmp_down_if_name);
		return 0;
	}
#if defined(__DAVO__)
	if (wanlink==LINK_DOWN) {
		return 0;
	}
#endif
#if defined (CONFIG_IGMPV3_SUPPORT)
    int		totalsize=0;
    igmpv3            = (struct igmpv3_query *)send_buf;
    igmpv3->type      = 0x11;
    igmpv3->code      = mrt;
    igmpv3->csum      = 0;
    igmpv3->group     = grp;
    igmpv3->resv      = 0;
    igmpv3->suppress  = 1;
    igmpv3->qrv       = 2;
    igmpv3->qqic      = PERIODICAL_GENERAL_QUERY_INTERVAL;
    igmpv3->nsrcs     = 0;
    totalsize	      = sizeof(struct igmpv3_query)+igmpv3->nsrcs*sizeof(__u32);
    igmpv3->csum      = in_cksum((u_short *)igmpv3, totalsize );
#else
   igmp               = (struct igmphdr *)(send_buf);
    igmp->type         = 0x11;
    igmp->code         = mrt;
    igmp->group 	   = grp;
    igmp->csum        = 0;
    igmp->csum        = in_cksum((u_short *)igmp, IGMP_MINLEN);
#endif

    bzero(&sdst, sizeof(struct sockaddr_in));
    sdst.sin_family = AF_INET;
    sdst.sin_addr.s_addr = dst;

#if defined (CONFIG_IGMPV3_SUPPORT)
    if (sendto(dp->sock, igmpv3, totalsize, 0, (struct sockaddr *)&sdst, sizeof(sdst)) < 0)
    {
	printf("igmpv3_query> sendto error, from %s ", inet_ntoa(dp->InAdr.s_addr));
	printf("to %s\n", inet_ntoa(sdst.sin_addr.s_addr));
    }
#else
    //printf("send igmp query\n");
#if defined(__DAVO__)
	if ( grp )
		sprintf(grp_addr, "(%u.%u.%u.%u)", NIPQUAD(grp));

	if ( !access("/var/igmp_log", F_OK) )
		syslog(LOG_DEBUG, "IGMP %s Query%s MRT %u(1/10 sec)", ((grp)?"Specific": "Gerenal"),((grp)?grp_addr:""), mrt);

#endif
    if (sendto(dp->sock, igmp, IGMP_MINLEN, 0,
			(struct sockaddr *)&sdst, sizeof(sdst)) < 0) {
		fprintf(stderr, "%s: %s: %u.%u.%u.%u > %u.%u.%u.%u\n", __func__,
				strerror(errno), NIPQUAD(dst), NIPQUAD(grp));
    }
#endif

    return 0;

}


/*
 * igmp_leave - send an IGMP LEAVE packet, directly to linkp->send(), not via ip
 *
 * int igmp_leave( longword ina, int ifno )
 * Where:
 *  	ina	the IP address to leave
 *  	ifno	interface number
 *
 * Returns:
 *	0	if unable to send leave
 *	1	report was sent successfully
 */

int igmp_leave(__u32 grp, int if_idx)
{
    struct iphdr *ip;
    struct igmphdr *igmp;
    struct sockaddr_in sdst;
	struct IfDesc *dp;
	int index;
#ifdef CONFIG_IGMPPROXY_MULTIWAN
	int null_cnt=0;
	int err_cnt=0;
#endif

    ip              = (struct iphdr *)send_buf;
    ip->daddr       = ALL_ROUTERS;
    ip->tot_len              = MIN_IP_HEADER_LEN + IGMP_MINLEN;
	ip->ttl = 1;

    igmp               = (struct igmphdr *)(send_buf + MIN_IP_HEADER_LEN);
   	igmp->type         = 0x17;
    igmp->code         = 0;
    igmp->group 	   = grp;
    igmp->csum        = 0;
    igmp->csum        = in_cksum((u_short *)igmp, IGMP_MINLEN);

    bzero(&sdst, sizeof(struct sockaddr_in));
    sdst.sin_family = AF_INET;
    sdst.sin_addr.s_addr = ALL_ROUTERS;
    //printf("send igmp leave\n");
    //syslog(LOG_INFO, "igmpproxy: send leave to %s: %s\n", igmp_up_if_name, inet_ntoa(grp));

    // Kaohj
#ifdef CONFIG_IGMPPROXY_MULTIWAN
	for(index=0;index<igmp_up_if_num;index++)
	{
		dp= getIfByName(igmp_up_if_name[index]);

		if(dp==NULL){
			null_cnt++;
			continue;
		}
		ip->saddr       = dp->InAdr.s_addr;
		if (sendto(dp->sock, igmp, IGMP_MINLEN, 0,
				(struct sockaddr *)&sdst, sizeof(sdst)) < 0) {
			err_cnt++;
			printf("igmp_leave> sendto error, from %s ", inet_ntoa(ip->saddr));
			printf("to %s\n", inet_ntoa(ip->daddr));
		}
    }
	if ((null_cnt>=igmp_up_if_num)||(err_cnt>=igmp_up_if_num))
		return 0;

#else
	// Kaohj
	dp = getIfByName(igmp_up_if_name);
	if (!dp)
		return 0;
	ip->saddr       = dp->InAdr.s_addr;
    if (sendto(dp->sock, igmp, IGMP_MINLEN, 0, (struct sockaddr *)&sdst, sizeof(sdst)) < 0) {
		printf("igmp_leave> sendto error, from %s ", inet_ntoa(ip->saddr));
		printf("to %s\n", inet_ntoa(ip->daddr));
		return 0;
    }
#endif

    return 1;
}






////////////////////////////////////////////////////////////////////////////////////


char* runPath = "/bin/igmpproxy";
char* pidfile = "/var/run/igmp_pid";

#if 0
static void clean(void)
/*
** Cleans up, i.e. releases allocated resources. Called via atexit().
**
*/
{
  log( LOG_DEBUG, 0, "clean handler called" );
  disableMRouter();

  unlink(pidfile);
  exit(EXIT_SUCCESS);
}
#endif

/*
 * On hangup, let everyone know we're going away.
 */

void hup(int signum)
{
	(void)signum;

  log( LOG_DEBUG, 0, "clean handler called" );
#ifdef	IGMP_MCAST2UNI
  Update_igmpProxyStateToKernel(0);
#endif
  disableMRouter();
  LOG(LOG_INFO, "IGMP proxy stop(%d)", signum);
  unlink(pidfile);
  exit(EXIT_SUCCESS);

}
#ifdef CONFIG_CHECK_MULTICASTROUTE
void singnalAlrm(int signum)
{
	(void)signum;
	int checkroute=0;

	checkroute=check_kernel_multicast_route(1);
	if(check_entry1==1 && checkroute==0){
		system("route add -net 224.0.0.0 netmask 240.0.0.0 dev br0 2> /dev/null");
		check_entry1=0;
	}
	checkroute = 0;
	checkroute=check_kernel_multicast_route(2);
	if( check_entry2==1 && checkroute ==0){
		system("route add -net 255.255.255.255 netmask 255.255.255.255 dev br0 2> /dev/null");
		check_entry2=0;
	}
	if(check_multicast_route ==1)
		check_multicast_route= 0;

}
#endif

// Kaohj added
// Comes here because upstream or downstream interface ip changed
// Usually, it is used by dynamic interface to sync its interface with
// the igmpproxy local database.
void sigifup(int signum)
{
	(void)signum;
	struct ifreq IfVc[ MAX_IF  ];
	struct ifreq *IfEp, *IfPt;
	struct ifconf IoCtlReq;
	struct IfDesc *Dup, *Ddp;
	int Sock;

	LOG(LOG_INFO, "igmpproxy: SIGUSR1 caught\n");
	// get information of all the interfaces
	if( (Sock = socket( AF_INET, SOCK_DGRAM, 0 )) < 0 )
		log( LOG_ERR, errno, "RAW socket open" );

	IoCtlReq.ifc_buf = (void *)IfVc;
	IoCtlReq.ifc_len = sizeof( IfVc );

	if( ioctl( Sock, SIOCGIFCONF, &IoCtlReq ) < 0 )
		log( LOG_ERR, errno, "ioctl SIOCGIFCONF" );

	close( Sock );
	IfEp = (void *)((char *)IfVc + IoCtlReq.ifc_len);
#ifdef CONFIG_IGMPPROXY_MULTIWAN
        int index;
     // get descriptors of upstream and downstream interfaces

	Ddp = getIfByName(igmp_down_if_name);
	if ( Ddp == NULL)
		return;

	// update upstream/downstream interface ip into local database
	for( IfPt = IfVc; IfPt < IfEp; IfPt++ ) {

		for(index = 0;index<igmp_up_if_num;index++)
	       {
	           Dup = getIfByName(igmp_up_if_name[index]);
		   if ( Dup == NULL)
		       continue;
		  igmp_up_if_idx[index] = addVIF(Dup);
		  if (!strcmp(IfPt->ifr_name, Dup->Name)) {
			Dup->InAdr = ((struct sockaddr_in *)&IfPt->ifr_addr)->sin_addr;
			//printf("update upstream ip to %s\n", inet_ntoa(Dup->InAdr));
			// Update default multicast interface for this socket.
			setsockopt(Dup->sock, IPPROTO_IP, IP_MULTICAST_IF,
				(void*)&Dup->InAdr, sizeof(struct in_addr));
		   }
	        }

	      if (!strcmp(IfPt->ifr_name, Ddp->Name)) {
			Ddp->InAdr = ((struct sockaddr_in *)&IfPt->ifr_addr)->sin_addr;
			//printf("update downstream ip to %s\n", inet_ntoa(Ddp->InAdr));
			// Update default multicast interface for this socket.
			setsockopt(Ddp->sock, IPPROTO_IP, IP_MULTICAST_IF,
				(void*)&Ddp->InAdr, sizeof(struct in_addr));
	      }
	}

#else
	// get descriptors of upstream and downstream interfaces
	Dup = getIfByName(igmp_up_if_name);
	Ddp = getIfByName(igmp_down_if_name);
	if (Dup == NULL || Ddp == NULL)
		return;

	// update upstream/downstream interface ip into local database
	for( IfPt = IfVc; IfPt < IfEp; IfPt++ ) {
		if (!strcmp(IfPt->ifr_name, Dup->Name)) {
			Dup->InAdr = ((struct sockaddr_in *)&IfPt->ifr_addr)->sin_addr;
			//printf("update upstream ip to %s\n", inet_ntoa(Dup->InAdr));
			// Update default multicast interface for this socket.
			setsockopt(Dup->sock, IPPROTO_IP, IP_MULTICAST_IF,
				(void*)&Dup->InAdr, sizeof(struct in_addr));
		}
		else if (!strcmp(IfPt->ifr_name, Ddp->Name)) {
			Ddp->InAdr = ((struct sockaddr_in *)&IfPt->ifr_addr)->sin_addr;
			//printf("update downstream ip to %s\n", inet_ntoa(Ddp->InAdr));
			// Update default multicast interface for this socket.
			setsockopt(Ddp->sock, IPPROTO_IP, IP_MULTICAST_IF,
				(void*)&Ddp->InAdr, sizeof(struct in_addr));
		}
	}
#endif
}

static int initMRouter(void)
/*
** Inits the necessary resources for MRouter.
**
*/
{
	int Err;
	int i;
	struct IfDesc *Ddp, *Dup;
	int proxyUp = 0;

	buildIfVc();

	switch( Err = enableMRouter() ) {
		case 0: break;
		case EADDRINUSE: log( LOG_ERR, EADDRINUSE, "MC-Router API already in use" ); break;
		default: log( LOG_ERR, Err, "MRT_INIT failed" );
	}
  #ifdef CONFIG_IGMPPROXY_MULTIWAN
        Ddp = getIfByName(igmp_down_if_name);

	if (Ddp==NULL )
		return 0;

	/* add downstream interface */
	igmp_down_if_idx = addVIF(Ddp);

	/* add upstream interface */
	 for(i = 0;i<igmp_up_if_num;i++)
	{
	           Dup = getIfByName(igmp_up_if_name[i]);
		   if ( Dup == NULL)
			   continue;
		   else
		   	proxyUp = 1;
		   igmp_up_if_idx[i] = addVIF(Dup);
         }

	if(proxyUp == 0)
	{
		return 0;
	}
   #else
	Ddp = getIfByName(igmp_down_if_name);
	Dup = getIfByName(igmp_up_if_name);
	if (Ddp==NULL || Dup==NULL)
		return 0;

	/* add downstream interface */
	igmp_down_if_idx = addVIF(Ddp);

	/* add upstream interface */
	igmp_up_if_idx = addVIF(Dup);
#endif

	signal(SIGTERM, hup);

#if defined (CONFIG_QUERIER_SELECTION)
	initQuerierSelection();
#endif

  //atexit( clean );
  	return 1;
}

#ifndef __DAVO__
void
write_pid()
{
	FILE *fp = fopen(pidfile, "w+");
	if (fp) {
		fprintf(fp, "%d\n", getpid());
		fclose(fp);
	}
	else
	 	printf("Cannot create pid file\n");
}

void
clear_pid()
{
	FILE *fp = fopen(pidfile, "w+");
	if (fp) {
		fprintf(fp, "%d\n", 0);
		fclose(fp);
	}
	else
	 	printf("Cannot create pid file\n");
}
#endif

extern int MRouterFD;

void callback_usr2()
{
	linkChangeQueryTimer.type=LIMIT_RETRY_TIMER_TYPE;
	linkChangeQueryTimer.retry_left=LINK_CHANGE_QUERY_TIMES;
	linkChangeQueryTimer.timerInterval=LINK_CHANGE_QUERY_INTERVAL;
	timeout(igmp_general_query_timer_expired , &linkChangeQueryTimer, linkChangeQueryTimer.timerInterval, &linkChangeQueryTimer.ch);
}

int main(int argc, char **argv)
{
	int _argc = 0;
#ifdef CONFIG_IGMPPROXY_MULTIWAN
        char *_argv[12];
		int index;		//
#else
	char *_argv[5];
#endif
	pid_t pid;
	int execed = 0;
	char cmdBuffer[50];//Brad add 20080605
	struct IfDesc *IfDp;
	int flags;
#if defined(__DAVO__)
	char tmp[80];
	int i;
	unsigned int flag;
	int flagfd, pid_fd;
#endif
#ifdef CONFIG_IGMPPROXY_MULTIWAN
       if (argc >= 12) {
#else
        if (argc >= 5) {
#endif
		fprintf(stderr, "To many arguments \n");
		exit(1);
	}
#ifndef __DAVO__
	if (strcmp(argv[argc-1], "-D") == 0) {
		argc--;
		execed = 1;
	}
#endif
	if(argc < 2) {
		printf("Usage: igmpproxy <up interface> [down interface]\n\n");
		return 0;
	}
#ifndef __DAVO__
	if (!execed) {
		if ((pid = vfork()) < 0) {
			fprintf(stderr, "vfork failed\n");
			exit(1);
		} else if (pid != 0) {
			exit(0);
		}

		for (_argc=0; _argc < argc; _argc++ )
			_argv[_argc] = argv[_argc];
		_argv[0] = runPath;
		_argv[argc++] = "-D";
		_argv[argc++] = NULL;
		execv(_argv[0], _argv);
		/* Not reached */
		fprintf(stderr, "Couldn't exec\n");
		_exit(1);

	} else {
		setsid();
	}
#endif

#if defined(__DAVO__)
	if (fcntl(STDIN_FILENO, F_GETFL) == -1)
		(void)open("/dev/null", O_RDONLY);
	if (fcntl(STDOUT_FILENO, F_GETFL) == -1)
		(void)open("/dev/null", O_WRONLY);
	if (fcntl(STDERR_FILENO, F_GETFL) == -1)
		(void)open("/dev/console", O_WRONLY);
#endif

#ifdef CONFIG_IGMPPROXY_MULTIWAN

        if(argc == 2)
		strcpy(igmp_down_if_name, "eth0");
	else
		strcpy(igmp_down_if_name, argv[argc-1]);

        for(index=1;index<argc-1;index++)
	   strcpy(igmp_up_if_name[index-1], argv[index]);

         igmp_up_if_num=argc-2;

#else
	if(argc == 2)
		strcpy(igmp_down_if_name, "eth0");
	else
		strcpy(igmp_down_if_name, argv[2]);
	strcpy(igmp_up_if_name, argv[1]);
#endif

#ifdef CONFIG_IGMPPROXY_MULTIWAN
	for(index=0;index<igmp_up_if_num;index++)
	{
		yecho("/var/igmp_up", "%s", igmp_up_if_name[index]);
	}

#else
	yecho("/var/igmp_up", "%s", igmp_up_if_name);
	yecho("/proc/igmp_proxy_wan_dev", "%s", igmp_up_if_name);
#endif
#ifndef __DAVO__
	write_pid();
#else
	pid_fd = pidfile_acquire(pidfile);
	pidfile_write_release(pid_fd);

	memset(&igmp_limite, 0, sizeof(struct dv_igmp_limite));
	init_timeout_value();

	nvram_get_r_def("x_igmp_version", tmp, sizeof(tmp), "2");
	i = strtoul(tmp, NULL, 10);
	/* 0: (auto) 1:(version 1) 2:(version 2) */
	if (i >= 0 && i <= 3) {
		sprintf(tmp, "/proc/sys/net/ipv4/conf/%s/force_igmp_version", igmp_up_if_name);
		yecho(tmp, "%d", i);
	}
#endif
	#if defined(CONFIG_IGMPV3_SUPPORT)
	yecho("/proc/br_igmpVersion", "3");
	#else
	yecho("/proc/br_igmpVersion", "2");
	#endif
#ifndef __DAVO__
	/*here to set igmp proxy daemon pid to kernel*/
	{
		int br_socket_fd = -1;
		unsigned long arg[3];

		arg[0] = BRCTL_SET_IGMPPROXY_PID;	//shoulde be BRCTL_SET_MESH_PATHSELPID
		arg[1] = getpid();
		arg[2] = 0;

		if ((br_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{
			printf("create socket to connect bridge fail! \n");

		}
		else
		{
			ioctl(br_socket_fd, SIOCGIFBR, arg);
		}
		close(br_socket_fd);
	}
#endif
	signal(SIGHUP, hup);
	signal(SIGTERM, hup);
	signal(SIGUSR1, sigifup);
	signal(SIGUSR2, callback_usr2);
#ifdef CONFIG_CHECK_MULTICASTROUTE
	signal(SIGALRM,singnalAlrm);
#endif
#ifndef __DAVO__
	while (!initMRouter()) {
		// Kaohj, polling every 2 seconds
		//printf("initMRouter fail\n");
		sleep(2);
	}
#else
	if (!initMRouter()) {
		fprintf(stderr, "IGMP proxy failed to initMRouter!\n");
		exit(1);
	}
#endif
	LOG(LOG_INFO, "IGMP proxy start (%d pid)", getpid());
	init_igmp();
#ifdef	IGMP_MCAST2UNI
	Update_igmpProxyStateToKernel(1);
#endif

	//hyking:recv the sock for avoid dst cache refcnt issue.
	//2010-8-3
	IfDp = getIfByName(igmp_down_if_name);
	if(IfDp->sock > 0) {
		add_fd(IfDp->sock);
		flags = fcntl(IfDp->sock, F_GETFL);
		if (flags == -1 || fcntl(IfDp->sock, F_SETFL, flags | O_NONBLOCK) == -1)
		   	printf("Couldn't set %s to nonblock\n",igmp_down_if_name);

	}

#ifdef CONFIG_IGMPPROXY_MULTIWAN
	for(index=0;index<igmp_up_if_num;index++)
	{
		IfDp = getIfByName(igmp_up_if_name[index]);
		if(IfDp->sock > 0)
		{
			add_fd(IfDp->sock);
			flags = fcntl(IfDp->sock, F_GETFL);
			if (flags == -1 || fcntl(IfDp->sock, F_SETFL, flags | O_NONBLOCK) == -1)
			   	printf("Couldn't set sock of %s to nonblock\n",igmp_up_if_name[index]);
		}
	}

#else
	IfDp = getIfByName(igmp_up_if_name);
	if(IfDp->sock > 0) {
		add_fd(IfDp->sock);
		flags = fcntl(IfDp->sock, F_GETFL);
		if (flags == -1 || fcntl(IfDp->sock, F_SETFL, flags | O_NONBLOCK) == -1)
		   	printf("Couldn't set sock of %s to nonblock\n",igmp_up_if_name);
	}
#endif

	if(MRouterFD>0)	{
		add_fd(MRouterFD);
		flags = fcntl(MRouterFD, F_GETFL);
		if (flags == -1 || fcntl(MRouterFD, F_SETFL, flags | O_NONBLOCK) == -1)
		   	printf("Couldn't set MRouterFD to nonblock\n");

	}
#if defined(__DAVO__)
	SpecificQueryTimer.type = PERIODICAL_TIMER_TPYE;
	SpecificQueryTimer.retry_left = 2;
	SpecificQueryTimer.timerInterval = 60;
	timeout(send_specific_query_to_all, &SpecificQueryTimer, SpecificQueryTimer.timerInterval, &SpecificQueryTimer.ch);
#endif

#if defined(USE_STATIC_ENTRY_BUFFER)
	memset(mcft_entry_tbl, 0x00, sizeof(struct mcft_entry_en)*MAX_MFCT_ENTRY);
	memset(mbr_entry_tbl, 0x00, sizeof(struct mbr_entry_en)*MAX_MBR_ENTRY);
#endif

	DISPLAY_BANNER;

#if defined(__DAVO__)
	flagfd = open("/proc/dvflag", O_RDWR);
	flag = (DF_WANLINK);
	if (flagfd > -1) {
		if (ioctl(flagfd, DVFLGIO_SETMASK, &flag)) {
			printf("igmpproxy dvflag ioctl\n");
		} else {
			read(flagfd, (void *)&flag, sizeof(flag));
			wanlink = !!(flag&DF_WANLINK);
			add_fd(flagfd);
		}
	}
#endif

#if defined(__DAVO__)
	background();
	br_setpid();
#endif
	/* process loop */
/*2008-0919 add ,when l2pt disconnection or any reason ;when igmpProxy be restart
	should issue query first*/
#if defined(__DAVO__)
	igmp_query(ALL_SYSTEMS, 0, GENERAL_QUERY_MAX_RSP_TIME);
#else
	igmp_query(ALL_SYSTEMS, 0, 1);
#endif

	while(1)
	{
		fd_set in;
		struct timeval tv;
		int ret;
		int recvlen;

#ifdef CONFIG_IGMPV3_SUPPORT
		igmpv3_timer();
#endif

#if defined(__DAVO__)
		calltimeout(&tv);
#else
		calltimeout();
		tv.tv_sec = 0;
		tv.tv_usec = 100000;
#endif
		in = in_fds;

		ret = select(max_in_fd+1, &in, NULL, NULL, &tv);

		if( ret <= 0 ){
			//printf("igmp: timeout\n");
			continue;
		}

		if(FD_ISSET(MRouterFD, &in)) {
			recvlen = recvfrom(MRouterFD, recv_buf, RECV_BUF_SIZE, 0, NULL, &recvlen);
			if (recvlen > 0) {
				IfDp = getIfByName(igmp_down_if_name);
				if (IGMP_rx_enable)
				{
					#ifdef CONFIG_IGMPV3_SUPPORT
						igmpv3_accept(recvlen, IfDp);
					#else
						igmp_accept(recvlen, IfDp);
					#endif /*CONFIG_IGMPV3_SUPPORT*/
				}
			}
			else {
		    	if (errno != EINTR && errno !=EAGAIN)
					log(LOG_ERR, errno, "recvfrom multicast route sock");
			}
	     }

		//hyking:recv the sock for avoid dst cache refcnt issue.
		//2010-8-3
		IfDp =  getIfByName(igmp_down_if_name);
		if(FD_ISSET(IfDp->sock, &in)) {
			recvlen = recvfrom(IfDp->sock,recv_buf,RECV_BUF_SIZE, 0, NULL, &recvlen);

			if (recvlen < 0)
				if (errno != EINTR && errno !=EAGAIN) log(LOG_ERR, errno, "recvfrom down interface");
		}
#ifdef CONFIG_IGMPPROXY_MULTIWAN
		for(index=0;index<igmp_up_if_num;index++)
		{
			IfDp =  getIfByName(igmp_up_if_name[index]);
			if(FD_ISSET(IfDp->sock, &in))
			{
				if ( (recvlen = recvfrom(IfDp->sock,recv_buf,RECV_BUF_SIZE, 0, NULL, &recvlen)) < 0)
					if (errno != EINTR && errno !=EAGAIN)
						log(LOG_ERR, errno, "recvfrom up interface");
			}
		}

#else
		IfDp =  getIfByName(igmp_up_if_name);
		if(FD_ISSET(IfDp->sock, &in))
		{
			if ( (recvlen = recvfrom(IfDp->sock,recv_buf,RECV_BUF_SIZE,  0, NULL, &recvlen)) < 0)
				if (errno != EINTR && errno !=EAGAIN)
					log(LOG_ERR, errno, "recvfrom up interface");
		}
#endif
#if defined(__DAVO__)
		if (FD_ISSET(flagfd, &in)) {
			if (read(flagfd, (void *)&flag, sizeof(flag)) > 0) {
				wanlink = !!(flag&DF_WANLINK);
			}
		}
#endif
	}
#if defined(__DAVO__)
	if (flagfd > 0)
		close(flagfd);
#endif

	return 0;
}

#if defined(__DAVO__)
static const char *portname(int port)
{
	static char buffer[12];

	switch (port) {
	case -1:
		strcpy(buffer, "LAN-*");
		break;
	case 4:
		strcpy(buffer, "WAN");
		break;
	default:
		sprintf(buffer, "LAN-%d", (port+1));
		break;
	}
	return buffer;
}

static int locate_port(__u32 source, __u32 group, int *fwdmask)
{
	int fd, port = -1;
	struct mcfwd_req req;

	fd = open("/proc/brdio", O_RDWR);
	if (fd != -1) {
		req.source = source;
		req.group = group;
		if (ioctl(fd, MCFWD_MASK, &req) == 0) {
			port = req.port_no;
			if (fwdmask)
				*fwdmask = req.fwdmask;
		}
		close(fd);
	}

	return port;
}

static int init_timeout_value(void)
{
	char buf[20];

	nvram_get_r_def("x_igmp_expire_time", buf, sizeof(buf), "60");
	MEMBER_QUERY_INTERVAL = strtoul(buf, NULL, 10);

	nvram_get_r_def("x_igmp_query_interval", buf, sizeof(buf), "125");
	PERIODICAL_GENERAL_QUERY_INTERVAL = strtoul(buf, NULL, 10);

	nvram_get_r_def("x_igmp_query_res_interval", buf, sizeof(buf), "5");
	STARTUP_GENERAL_QUERY_INTERVAL = strtoul(buf, NULL, 10);

	nvram_get_r_def("IGMP_FAST_LEAVE_DISABLED", buf, sizeof(buf), "0");
	bFastLeave = !atoi(buf);

	nvram_get_r_def("x_igmp_joinlimit_enable", buf, sizeof(buf), "0");
	dv_igmp_limite_enabled(atoi(buf));

	nvram_get_r_def("x_igmp_limite_sys", buf, sizeof(buf), "128");
	dv_igmp_limite_set(4, atoi(buf));

	nvram_get_r_def("x_igmp_limite_lan1", buf, sizeof(buf), "32");
	dv_igmp_limite_set(0, atoi(buf));

	nvram_get_r_def("x_igmp_limite_lan2", buf, sizeof(buf), "32");
	dv_igmp_limite_set(1, atoi(buf));

	nvram_get_r_def("x_igmp_limite_lan3", buf, sizeof(buf), "32");
	dv_igmp_limite_set(2, atoi(buf));

	nvram_get_r_def("x_igmp_limite_lan4", buf, sizeof(buf), "32");
	dv_igmp_limite_set(3, atoi(buf));

	nvram_get_r_def("x_igmp_general_mrt", buf, sizeof(buf), "100");//10sec(in 1/10 second unit)
	GENERAL_QUERY_MAX_RSP_TIME = strtoul(buf, NULL, 10);
	return 0;
}

static void dv_igmp_limite_enabled(int enable)
{
	igmp_limite.enabled = enable;
	LOG(LOG_DEBUG, "Group count is %simited", (igmp_limite.enabled) ? "L" : "Unl");
}

static void dv_igmp_limite_set(int port, int limite)
{
	if (port > MAX_PORT)
		return;
	igmp_limite.limite[port] = limite;
}

static int dv_igmp_limite_check(__u32 source, __u32 group)
{
	struct dv_igmp_limite *p = &igmp_limite;
	int port, pmask, i;
	struct mcft_entry *mcp;
	struct mbr_entry *gcp;

	if (p->enabled == 0)
		return 1;

	port = locate_port(source, group, NULL);
	/* port0-port3: lan1-lan4 */
	if (port < 0 || port > 3) {
		LOG(LOG_DEBUG, "IGMP limit check, cant find port(%d)... \n", port);
		return 1;
	}

	memset(&p->current, 0, sizeof(p->current));
	for (mcp = mcpq; mcp; mcp = mcp->next) {
		for (gcp = mcp->grp_mbr; gcp; gcp = gcp->next) {
			pmask = 0;
			locate_port(gcp->user_addr, mcp->grp_addr, &pmask);
			for (i = 0; i < MAX_PORT; i++)
				if (pmask & (1 << i))
					p->current[i]++;
			/*
			 * total count
			 */
			if (pmask & 0xf)
				p->current[4]++;
		}
	}
	LOG(LOG_DEBUG, "IGMP Join lan%d limit check %d/%d [%d/%d]\n",
				(port+1), p->current[port], p->limite[port], p->current[4], p->limite[4]);

	return ((p->limite[4] > p->current[4]) && (p->limite[port] > p->current[port]));
}

static void send_specific_query_to_all(void *arg)
{
	struct mcft_entry *mcp = mcpq;

	while (mcp) {
		//printf("%-15s %-09d\n", inet_ntoa(mcp->grp_addr), mcp->user_count);
		mcp->timer.retry_left = MEMBER_QUERY_COUNT;
		timeout(igmp_specific_timer_expired2, mcp,
				LAST_MEMBER_QUERY_INTERVAL, &mcp->timer.ch);
		mcp = mcp->next;
	}
	timeout(send_specific_query_to_all, &SpecificQueryTimer,
			SpecificQueryTimer.timerInterval, &SpecificQueryTimer.ch);
}

static int pidfile_acquire(char *name)
{
	int pid_fd;
	if (name == NULL) return -1;

	pid_fd = open(name, O_CREAT | O_WRONLY, 0644);
	if (pid_fd < 0) {
		fprintf(stderr, "Unable to open pidfile %s: %s\n", name, strerror(errno));
	} else {
		lockf(pid_fd, F_LOCK, 0);
	}

	return pid_fd;
}

static void pidfile_write_release(int pid_fd)
{
	FILE *out;

	if (pid_fd < 0) return;

	if ((out = fdopen(pid_fd, "w")) != NULL) {
		fprintf(out, "%d\n", getpid());
		fclose(out);
	}
	lockf(pid_fd, F_UNLCK, 0);
	close(pid_fd);
}


static void pidfile_delete(char *name)
{
	if (name) unlink(name);
}

static void background(void)
{
	int pid_fd;

	pid_fd = pidfile_acquire(pidfile);	/* hold lock during fork. */
	while (pid_fd >= 0 && pid_fd < 3)
		pid_fd = dup(pid_fd);	/* don't let daemon close it */

	if (daemon(0, 1) == -1) {
		perror("fork");
		pidfile_delete(pidfile);
		exit(1);
	}

	pidfile_write_release(pid_fd);
}

static void br_setpid(void)
{
	int br_socket_fd;
	unsigned long arg[3];

	arg[0] = BRCTL_SET_IGMPPROXY_PID;	//shoulde be BRCTL_SET_MESH_PATHSELPID
	arg[1] = getpid();
	arg[2] = 0;

	if ((br_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror(__func__);
	} else {
		ioctl(br_socket_fd, SIOCGIFBR, arg);
		close(br_socket_fd);
	}
}

#endif


