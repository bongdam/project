/* General includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <linux/wireless.h>

/* SNMP includes */
#include "asn1.h"
#include "snmp.h"
#include "agt_mib.h"
#include "agt_engine.h"
#include "cjhv_mib.h"
#include "snmp_main.h"
#include "cjhv_api.h"

static inline int
iw_get_ext(int                  skfd,           /* Socket to the kernel */
			char *               ifname,         /* Device name */
			int                  request,        /* WE ID */
			struct iwreq *       pwrq)           /* Fixed part of the request */
{
	/* Set device name */
	strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);
	/* Do the request */
	return(ioctl(skfd, request, pwrq));
}

int getWlBssInfo(char *interface, bss_info *pInfo)
{
	int skfd = 0;
	struct iwreq wrq;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd == -1)
		return -1;
    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0)
      /* If no wireless name : no wireless extensions */
	{
		close( skfd );
		return -1;
	}

	wrq.u.data.pointer = (caddr_t)pInfo;
	wrq.u.data.length = sizeof(bss_info);

	if (iw_get_ext(skfd, interface, SIOCGIWRTLGETBSSINFO, &wrq) < 0) {
		close( skfd );
		return -1;
	}
	close( skfd );

	return 0;
}

int getMiscData(char *interface, struct _misc_data_ *pData)
{
	int skfd;
	struct iwreq wrq;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Get wireless name */
	if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0)
      /* If no wireless name : no wireless extensions */
        return -1;

	wrq.u.data.pointer = (caddr_t)pData;
	wrq.u.data.length = sizeof(struct _misc_data_);

	if (iw_get_ext(skfd, interface, SIOCGMISCDATA, &wrq) < 0)
		return -1;

	close(skfd);
	return 0;
}

int getWlSiteSurveyRequest(char *interface, int *pStatus)
{
	int skfd = 0;
	struct iwreq wrq;
	unsigned char result;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd == -1)
		return -1;

    /* Get wireless name */
    if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
		/* If no wireless name : no wireless extensions */
		close( skfd );
		return -1;
	}

	wrq.u.data.pointer = (caddr_t)&result;
	wrq.u.data.length = sizeof(result);

	if (iw_get_ext(skfd, interface, SIOCGIWRTLSCANREQ, &wrq) < 0) {
		close( skfd );
		return -1;
	}
    close(skfd);

    if ( result == 0xff )
		*pStatus = -1;
    else
		*pStatus = (int)result;

	return 0;
}

int getWlSiteSurveyResult(char *interface, SS_STATUS_Tp pStatus)
{
	int skfd = 0;
	struct iwreq wrq;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd == -1)
		return -1;

	/* Get wireless name */
	if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
		/* If no wireless name : no wireless extensions */
		close( skfd );
		return -1;
	}

	wrq.u.data.pointer = (caddr_t)pStatus;
	wrq.u.data.length = sizeof(SS_STATUS_T);

	if (iw_get_ext(skfd, interface, SIOCGIWRTLGETBSSDB, &wrq) < 0) {
		close( skfd );
		return -1;
	}
	close( skfd );

    return 0;
}

int getWlStaInfo( char *interface,  WLAN_STA_INFO_Tp pInfo)
{
	int skfd = 0;
	struct iwreq wrq;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd == -1)
		return -1;
	/* Get wireless name */
	if ( iw_get_ext(skfd, interface, SIOCGIWNAME, &wrq) < 0) {
		/* If no wireless name : no wireless extensions */
		close( skfd );
		return -1;
	}

	wrq.u.data.pointer = (caddr_t)pInfo;
	wrq.u.data.length = sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM + 1);
	memset(pInfo, 0, sizeof(WLAN_STA_INFO_T) * (MAX_STA_NUM + 1));

	if (iw_get_ext(skfd, interface, SIOCGIWRTLSTAINFO, &wrq) < 0) {
		close( skfd );
		return -1;
	}

	close( skfd );
	return 0;
}
