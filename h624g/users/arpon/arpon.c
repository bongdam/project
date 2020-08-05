/* 
 * Copyright (C) 2008-2014 Andrea Di Pasquale <spikey.it@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice(s), this list of conditions and the following disclaimer as
 *    the first lines of this file unmodified other than the possible
 *    addition of one or more copyright notices.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice(s), this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER(S) ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * $ArpON: arpon.c,v 2.7.2 10/14/2014 03:56:04 Andrea Di Pasquale Exp $
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ether.h>

#include <pthread.h>
#include <pcap.h>
#include <pcap/bpf.h>
//#include "bpf.h"

#include "dnet.h"

#include "include/queue.h"

#include "config.h"

#include <libnet.h>

#if defined NETBSD || defined OPENBSD || defined LINUX || defined SOLARIS
#define	octet   ether_addr_octet
#endif /* struct ether addr. */

#define ERROR(str)  fprintf(stderr, "ERROR: %s:%d %s.\n\n",    \
                            __FILE__, __LINE__, str)

enum iface_t { IFACE_MANUAL, IFACE_AUTO, IFACE_LIST, IFACE_NULL };
enum inspec_t { INSPEC_SARPI, INSPEC_DARPI, INSPEC_HARPI, INSPEC_NULL };

struct iface {
    char dev[IF_NAMESIZE];
    int dev_offset;
    struct ether_addr dev_mac;
    struct in_addr dev_inet4;
    struct in_addr dev_netmask;
};

struct arp_header {	
    /* 
     * ARP header.
     */
    struct arp_hdr ah_header;
    /* 
     * Ethernet header. 
     */
    struct arp_ethip ah_addresses;
};

/*
 * For libdnet.
 * Required for arp_t fileno.
 */
struct arp_handle {
    int fd;
    int seq;
};

struct arp_cache {	
    TAILQ_ENTRY(arp_cache) entries;
    struct ether_addr ac_mac;
    struct in_addr ac_ip;
};

struct sarpi_cache {
    TAILQ_ENTRY(sarpi_cache) entries;
    struct ether_addr sc_mac;
    struct in_addr sc_ip;
};

struct darpi_cache1 {
    TAILQ_ENTRY(darpi_cache1) entries;
    struct in_addr dc_ip;
    time_t tm_entry;
};

struct darpi_cache2 {
    TAILQ_ENTRY(darpi_cache2) entries;
    struct in_addr dc_ip;
    time_t tm_entry;
};

struct darpi_cache3 {
    TAILQ_ENTRY(darpi_cache3) entries;
    struct in_addr dc_ip;
    time_t tm_entry;
};

static int       task_mode_cpu_priority(int, int, int);
static int       task_mode_daemon(void);
static FILE     *task_mode_pid_open(void);
static void      task_mode_pid_close(FILE *);
static int       task_mode_log(void);
static FILE     *task_mode_log_open(void);
static void      task_mode_log_close(FILE *);
static int       iface_manager(void);
static int       iface_check_uplink(void);
static void      iface_check_uplink_thread_sigusr1(int);
static void     *iface_check_uplink_thread(void *);
static void      iface_set_name(char *);
static void      iface_unset_name(void);
static int       iface_check_datalink(char *);
static int       iface_check_running(void);
static int       iface_check_online(void);
static void      iface_check_online_packet(unsigned char *,
    const struct pcap_pkthdr *, const unsigned char *); 
static int       iface_del_promisc(void);
static int       iface_get_mac_address(void);
static int       iface_get_inet4_addresses(void);
static void      iface_info_print(void);
static arp_t    *arp_cache_open(void);
static void      arp_cache_close(arp_t *);
static int       arp_cache_add(char *);
static int       arp_cache_del(char *);
static int       arp_cache_del_all(void);
static int       arp_cache_list_create(const struct arp_entry *, void *);
static void      arp_cache_list_destroy(void);
static int       sarpi_set_timeout(char *);
static void      sarpi_manager_thread_sigusr1(int);
static void     *sarpi_manager_thread(void *);
static int       sarpi_realtime(void);
static void      sarpi_realtime_thread_sigusr1(int);
static void     *sarpi_realtime_thread(void *);
static pcap_t   *sarpi_realtime_open_packets(void);
static void      sarpi_realtime_close_packets(pcap_t *);
static void      sarpi_realtime_read_packets(unsigned char *, 
    const struct pcap_pkthdr *, const unsigned char *);
static int       sarpi_cache_file_restore(void);
static int       sarpi_cache_list_create(const struct arp_entry *, void *);
static void      sarpi_cache_list_refresh_thread_sigusr1(int);
static void     *sarpi_cache_list_refresh_thread(void *);
static void      sarpi_cache_list_destroy(void);
static int       darpi_set_timeout(char *);
static void      darpi_manager_thread_sigusr1(int);
static void     *darpi_manager_thread(void *);
static int       darpi_realtime(void);
static void      darpi_realtime_thread_sigusr1(int);
static void     *darpi_realtime_thread(void *);
static pcap_t   *darpi_realtime_open_packets(void);
static void      darpi_realtime_close_packets(pcap_t *);
static void      darpi_realtime_read_packets(unsigned char *, 
    const struct pcap_pkthdr *, const unsigned char *);
static int       darpi_realtime_send_packet(struct in_addr *);
static int       darpi_cache1_list_create(struct in_addr *);
static void      darpi_cache1_list_check_thread_sigusr1(int);
static void     *darpi_cache1_list_check_thread(void *);
static void      darpi_cache1_list_destroy(void);
static int       darpi_cache2_list_create(struct in_addr *);
static void      darpi_cache2_list_check_thread_sigusr1(int);
static void     *darpi_cache2_list_check_thread(void *);
static void      darpi_cache2_list_destroy(void);
static int       darpi_cache3_list_create(struct in_addr *);
static void      darpi_cache3_list_check_thread_sigusr1(int);
static void     *darpi_cache3_list_check_thread(void *);
static void      darpi_cache3_list_destroy(void);
static void      harpi_manager_thread_sigusr1(int);
static void     *harpi_manager_thread(void *);
static int       harpi_realtime(void);
static void      harpi_realtime_thread_sigusr1(int);
static void     *harpi_realtime_thread(void *);
static pcap_t   *harpi_realtime_open_packets(void);
static void      harpi_realtime_close_packets(pcap_t *);
static void      harpi_realtime_read_packets(unsigned char *, 
    const struct pcap_pkthdr *, const unsigned char *);
static void      aprintf(FILE *, int, char *, ...);
static void      license(void);
static void      version(void);
static void      help(void);
static int       main_signal(void);
static void     *main_signal_thread(void *);
static int       main_start(void);
static void      main_stop(void);

/*
 * iface informations.
 */
static struct iface dev;
/*
 * ARP cache.
 */
static struct arp_cache *arp_cache_begin, *arp_cache_next, *arp_cache_pos;
static TAILQ_HEAD(, arp_cache) arp_cache_head;
/*
 * SARPI cache.
 */
static struct sarpi_cache *sarpi_cache_begin, *sarpi_cache_next,
    *sarpi_cache_pos;
static TAILQ_HEAD(, sarpi_cache) sarpi_cache_head;
/*
 * DARPI 1 cache.
 */
static struct darpi_cache1 *darpi_cache1_begin, *darpi_cache1_next, 
    *darpi_cache1_pos;
static TAILQ_HEAD(, darpi_cache1) darpi_cache1_head;
/*
 * DARPI 2 cache.
 */
static struct darpi_cache2 *darpi_cache2_begin, *darpi_cache2_next, 
    *darpi_cache2_pos;
static TAILQ_HEAD(, darpi_cache2) darpi_cache2_head;
/*
 * DARPI 3 cache.
 */
static struct darpi_cache3 *darpi_cache3_begin, *darpi_cache3_next, 
    *darpi_cache3_pos;
static TAILQ_HEAD(, darpi_cache3) darpi_cache3_head;
/*
 * Signal handler.
 */
static sigset_t sigse;
/* 
 * Thread handler for:
 *  thread[0] = Signal handler
 *  thread[1] = SARPI/DARPI/HARPI manager
 *  thread[2] = Iface uplink handler
 *  thread[3] = SARPI/DARPI/HARPI
 *  thread[4] = SARPI/DARPI/HARPI
 *  thread[5] = DARPI/HARPI
 *  thread[6] = DARPI/HARPI
 *  thread[7] = HARPI.
 */
static pthread_t thread[8];
static pthread_attr_t join_attr, detach_attr;
static pthread_rwlock_t rlock, wlock, rlock2, wlock2, 
    rlock3, wlock3, rlock4, wlock4;
/* 
 * Default nice value for CPU priority.
 */
static int cpu_priority = 0;
/*
 * Default pid file.
 */
static char *pid_file = "/var/run/arpon.pid";
static pid_t pid_main;
/*
 * Default log file.
 */
static char *log_file = "/var/log/arpon.log";
/* 
 * Default log mode, with -1 is off.
 */
static int log_mode = -1;
/*
 * Default SARPI cache file.
 */
static char *sarpi_cache_file = arpon_sarpi;
/* 
 * Default ARP cache refresh timeout, 5 minuts.
 */
static int sarpi_timeout = 5;
/* 
 * Default DARPI cache entry timeout, 5 seconds.
 */
static int darpi_timeout = 5;
/*
 * Device name.
 */
static char *ddev = NULL;
/*
 * Default Iface type.
 */
static enum iface_t dif = IFACE_NULL;
/*
 * Default Inspection type.
 */
static enum inspec_t dinspec = INSPEC_NULL;

/**********************
 * Task mode handler: *
 **********************/

/* 
 * Sets CPU priority for who.
 */
static int 
task_mode_cpu_priority(int which, int who, int prio)
{
	
    if (cpu_priority != 0) {
        if (setpriority(which, who, prio) < 0) {
            ERROR(strerror(errno));
	    
            return (-1);
        }
    }

    return (0);
}

/* 
 * Demonize the process. 
 */
static int
task_mode_daemon(void)
{
    struct stat stats;
    FILE *pid_fstream;	
    int fd;

    if ((pid_fstream = task_mode_pid_open()) == NULL) {
    	return (-1);
    }

    if (stat(pid_file, &stats) < 0) {
        aprintf(stderr, 0, "ERROR: %s\n\n", strerror(errno));
		
        return (-1);
    }

    task_mode_pid_close(pid_fstream);

    if (S_ISREG(stats.st_mode) == 0) {
        aprintf(stderr, 0, "ERROR: %s is not a regular file.\n\n", pid_file);
		
        return (-1);
    }

    aprintf(stdout, 1, "PID = <%s>\n\n", pid_file);

    switch (fork()) { 
    case (-1):
        ERROR(strerror(errno));
        return (-1);
		
    case (0):
        break;
        	
    default:
        exit(EXIT_SUCCESS);	
    }

    if (setsid() < 0) {
        ERROR(strerror(errno));
		
        return (-1);
    }

    /* 
     * PID CPU Scheduling.
     */	
    if (task_mode_cpu_priority(PRIO_PROCESS, getpid(), cpu_priority) < 0) {
        return (-1);
    }

    /* 
     * Write arpon.pid file.
     */
    if ((pid_fstream = task_mode_pid_open()) == NULL) {
        kill(pid_main, SIGTERM);
		
        exit(EXIT_FAILURE);
    }
	
    fprintf(pid_fstream, "%d\n", (int)getpid());
    fflush(pid_fstream);
    task_mode_pid_close(pid_fstream);
	
    if ((fd = open("/dev/null", O_RDWR, 0)) < 0) {
        ERROR(strerror(errno));
		
        return (-1);
    }

    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
		
    if (fd > 2) {
        close(fd);
    }

    return (0);
}

/* 
 * Open pid file.
 */
static FILE *
task_mode_pid_open(void)
{
    FILE *pid_fstream;

    if ((pid_fstream = fopen(pid_file, "w+")) == NULL) {
        aprintf(stderr, 0, "ERROR: %s: %s\n\n", pid_file, strerror(errno));
		
        return (NULL);
    }

    return (pid_fstream);
}

/* 
 * Close pid file.
 */
static void
task_mode_pid_close(FILE *pid_fstream)
{

    if (pid_fstream != NULL) {
        fclose(pid_fstream);
    }
}


/* 
 * Logging mode.
 */
static int 
task_mode_log(void)
{
    struct stat stats;
    FILE *log_fstream;

    if ((log_fstream = task_mode_log_open()) == NULL) {
        return (-1);
    }

    if (stat(log_file, &stats) < 0) {
        aprintf(stderr, 0, "ERROR: %s: %s\n\n", log_file, strerror(errno));
		
        return (-1);
    }

    task_mode_log_close(log_fstream);

    if (S_ISREG(stats.st_mode) == 0) {
        aprintf(stderr, 0, "ERROR: %s is not a regular file.\n\n", log_file);
		
        return (-1);
    }

    /* 
     * Logging mode:
     *  0: on
     * -1: off.
     */
    log_mode = 0;

    return (0);
}

/* 
 * Open log file.
 */
static FILE * 
task_mode_log_open(void)
{
    FILE *log_fstream;

    if ((log_fstream = fopen(log_file, "a+")) == NULL) {
        aprintf(stderr, 0, "ERROR: %s: %s\n\n", log_file, strerror(errno));
		
        return (NULL);
    }

    return (log_fstream); 
}

/* 
 * Close log file.
 */
static void
task_mode_log_close(FILE *log_fstream)
{

    if (log_fstream != NULL) {
        fclose(log_fstream);
    }
}

/*******************
 * iface Handler: *
 *******************/

/* 
 * Handles the network iface with following modes:
 *  - Manual,
 *  - Automatic (First iface that can to be used), 
 *  - Listing eventual network ifaces.
 *  - boot/unplug/hibernation/suspension interface
 *
 * Doing the following operations:
 *  - Verifying Datalink 
 *  - Selecting the network iface to be used
 *  - Verifying iface running
 *  - Veryfying iface online ready
 *  - Putting down the promiscue flag if found set
 *  - Reading MAC Address
 *  - Reading IP, netmask inet4 addresses
 *  - Printing out network ifaces dates.
 */
static int
iface_manager(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *ifc;
	
    if (pcap_findalldevs(&ifc, errbuf) < 0) { 
        ERROR(errbuf);
        
        return (-1);
    }	
	
    /*
     * For SARPI and DARPI.
     */
    if (dif == IFACE_NULL) {
        dif = IFACE_AUTO;
    }
	
    for (; ifc != NULL; ifc = ifc->next) { 
        switch (dif) {
        case (IFACE_MANUAL):
            if (strncmp(ddev, ifc->name, IF_NAMESIZE) == 0) {
                if ((ifc->flags & PCAP_IF_LOOPBACK) == 0) { 
                    if (iface_check_datalink(ifc->name) < 0) { 
                        aprintf(stderr, 0, "ERROR: %s interface's datalink " \
                                "is not supported!\n\n", ddev);			
                        pcap_freealldevs(ifc);

                        exit(-1); 
                    }			
						
                    iface_set_name(ifc->name);
						
                    if (iface_del_promisc() < 0 || 
                        iface_get_mac_address() < 0 ||
                        iface_get_inet4_addresses() < 0) {
                        pcap_freealldevs(ifc);

                        exit(-1);
                    }
		    
                    pcap_freealldevs(ifc);		
                    
                    return (0);
                } else {
                    aprintf(stderr, 0, "ERROR: %s interface is not " \
                            "supported!\n\n", ddev);
                    pcap_freealldevs(ifc);

                    exit(-1);
                }
            }
            break;
				
        case (IFACE_AUTO):
            if ((ifc->flags & PCAP_IF_LOOPBACK) == 0) {
                if (iface_check_datalink(ifc->name) < 0) {
                    break;
                }
					
                iface_set_name(ifc->name);
					
                if (iface_del_promisc() < 0 ||
                    iface_get_mac_address() < 0 ||
                    iface_get_inet4_addresses() < 0) {
                    iface_unset_name();
						
                    break;
                }
					
                pcap_freealldevs(ifc);

                return (0);
            }
            break;
				
        case (IFACE_LIST):
            if ((ifc->flags & PCAP_IF_LOOPBACK) == 0) {
                if (iface_check_datalink(ifc->name) < 0) {
                    break;
                }
					
                iface_set_name(ifc->name);
					
                if (iface_del_promisc() < 0 || 
                    iface_get_mac_address() < 0 ||
                    iface_get_inet4_addresses() < 0) {
                    pcap_freealldevs(ifc);

                    return (-1);
                }
            }
            break;
				
        default:
            break;
        }   
    }
	
    if (dif == IFACE_MANUAL) {
        if (strncmp(ddev, dev.dev, IF_NAMESIZE) != 0) {
            aprintf(stderr, 0, "ERROR: %s interface not found!\n\n", ddev);
            pcap_freealldevs(ifc);

            exit(-1);
        }
    } else if (dif == IFACE_AUTO) {
        if (dev.dev[0] == '\0') {
            aprintf(stderr, 0, "ERROR: Interface not found!\n\n");
            pcap_freealldevs(ifc);

            exit(-1);
        }
    }
	
    pcap_freealldevs(ifc);
    return (0);
}

/*
 * Check automatically iface uplink:
 *  - boot
 *  - unplug ethernet/wireless
 *  - hibernation
 *  - suspension
 */
static int
iface_check_uplink(void)
{
	
    pthread_attr_init(&join_attr);
    pthread_attr_setschedpolicy(&join_attr, SCHED_RR);
	
    /*
     * Thread 3 joinabled, checks automatically iface uplink. 
     */
    if (pthread_create(&thread[2], &join_attr, 
        iface_check_uplink_thread, (void *) NULL) != 0) {
        ERROR(strerror(errno));
		
        pthread_attr_destroy(&join_attr);
        exit(-1);
    }
	
    pthread_attr_destroy(&join_attr);
    return (0);
}

/* 
 * Iface uplink signal handler.
 */
static void
iface_check_uplink_thread_sigusr1(int sig)
{
	
    pthread_exit((void *) 0);
}

/*
 * Check automatically iface uplink.
 * If uplink is down stops daemon, waits uplink up
 * and restart the daemon.
 */
static void *
iface_check_uplink_thread(void *arg)
{
    struct sigaction saction;
    int ret, ret2;

#ifdef NETBSD
    saction.sa_flags = 0;
#endif
    saction.sa_handler = iface_check_uplink_thread_sigusr1;
	
    if (sigaction(SIGUSR1, &saction, NULL) < 0) {
        ERROR(strerror(errno));
		
        pthread_exit((void *) -1);
    }
	
    while (1) {
        if ((ret = iface_check_running()) < 0) {
            pthread_exit((void *) -1);
        } else if (ret > 0) {
            /*
             * iface down/suspend.
             */
			
            while (1) {
                if ((ret2 = iface_check_running()) < 0) {
                    pthread_exit((void *) -1);
                } else if (ret2 == 0) {
                    /*
                     * Iface up/restore.
                     * Reboot the daemon.
                     */
                    kill(0, SIGHUP);
                    break;
                }
				
                /*
                 * Check each 1 second.
                 */
                sleep(1);
            }
        }
		
        /*
         * Iface up.
         * Check each 1 second.
         */
        sleep(1);
    }
	
    pthread_exit((void *) 0);
}

/*
 * Sets the network iface.
 */
static void
iface_set_name(char *name)
{
    memset(dev.dev, '\0', IF_NAMESIZE);
    strncpy(dev.dev, name, IF_NAMESIZE);
}

/*
 * Unset the network iface.
 */
static void
iface_unset_name(void)
{

    memset(dev.dev, '\0', IF_NAMESIZE);
}

/*
 * Checks the datalink. Accepting EN10MB only 
 * (and so only ethernet and wireless ifaces).
 */
static int
iface_check_datalink(char *devarg)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;
    int datalink;	

    if ((pcap = pcap_open_live(devarg, BUFSIZ, 0, 0, errbuf)) == NULL) {
        ERROR(errbuf);

        return (-1);
    }
    

    if ((datalink = pcap_datalink(pcap)) < 0) {
        ERROR(pcap_geterr(pcap));

        return (-1);
    }


    /* 
     * Set network offset if it is 
     * ethernet network iface.
     */
    if (datalink == DLT_EN10MB) {
        dev.dev_offset = 14;
        pcap_close(pcap);
        return (0);
    }

    pcap_close(pcap);

    return (-1);
}

/*
 * Checks if iface is running.
 */
static int
iface_check_running(void)
{
    struct ifreq ifr;
    int sd;
	
    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        ERROR(strerror(errno));
		
        return (-1);
    }
	
    memset(ifr.ifr_name, '\0', IF_NAMESIZE);
    strncpy(ifr.ifr_name, dev.dev, IF_NAMESIZE);
		
    if (ioctl(sd, SIOCGIFFLAGS, &ifr) < 0) {
        ERROR(strerror(errno));
        close(sd);
			
        return (-1);
    }
	
    /*
     * iface is not running.
     */
    if ((ifr.ifr_flags & IFF_RUNNING) == 0) {
        close(sd);
		
        return (1);
    }
	
    /*
     * iface running.
     */
    close(sd);
	
    return (0);
}

/*
 * Wait first packet for online check.
 */
static int
iface_check_online(void)
{
    struct bpf_program compiled_filter;
    char errbuf[PCAP_ERRBUF_SIZE], *filter = "arp";
    pcap_t *pcap;
    int ret;
#ifndef LINUX
    unsigned int op = 1;
#endif
	
    if ((pcap = pcap_open_live(dev.dev, BUFSIZ, 0, 0, errbuf)) == NULL) {
        ERROR(errbuf);

        return (-1);
    }
	
#ifndef LINUX
    /*
     * BSD, differently from linux does not
     * support automatic socket soft real time
     * (Linux Socket Filter).
     * Therefore on BSD platform it's necessary
     * to use this I/O Control.
     */
    if (ioctl(pcap_fileno(pcap), BIOCIMMEDIATE, &op) < 0) {
        ERROR(strerror(errno));
        pcap_close(pcap);
	
        return (-1);
    }
#endif
	
    if (pcap_compile(pcap, &compiled_filter, 
        filter, 0, dev.dev_netmask.s_addr) < 0) {
        ERROR(pcap_geterr(pcap));
        pcap_close(pcap);
	
        return (-1);
    }
	
    if (pcap_setfilter(pcap, &compiled_filter) < 0) {
        ERROR(pcap_geterr(pcap));
        pcap_close(pcap);
		
        return (-1);
    }
	
    /*
     * Wait first packet.
     */
    if ((ret = pcap_loop(pcap, 1, iface_check_online_packet, NULL)) < 0) {
        pcap_freecode(&compiled_filter);

        switch (ret) {
        case (-1):
            ERROR(pcap_geterr(pcap));
            pcap_close(pcap);

            return (-1);

        case (-2):
        default:
            pcap_close(pcap);
            /* 
             * Offline.
             */
            return (1);
        }
    }

    /*
     * Online.
     */
	
    pcap_freecode(&compiled_filter);
    pcap_close(pcap);
		
    return (0);
}

/*
 * Wait an ARP packet.
 */
static void
iface_check_online_packet(unsigned char *arg, const struct pcap_pkthdr
    *header, const unsigned char *packet)
{

    /*
     * ARP traffic is ok.
     */
    return;
}

/*
 * Putting down the promiscue flag if 
 * found set in network iface.
 */
static int
iface_del_promisc(void)
{	
    struct ifreq ifr;
    int sd;
	
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        ERROR(strerror(errno));
		
        return (-1);
    }
	
    strncpy(ifr.ifr_name, dev.dev, sizeof(char) * IF_NAMESIZE);
    ifr.ifr_name[sizeof(char) * strlen(ifr.ifr_name)] = '\0';
	
    if (ioctl(sd, SIOCGIFFLAGS, &ifr) < 0) {
        ERROR(strerror(errno));
        close(sd);

        return (-1);
    }

    if (ifr.ifr_flags & IFF_PROMISC) {
        /* 
         * Remove Promisc flag 
         */
        ifr.ifr_flags &= ~IFF_PROMISC;
		
        if (ioctl(sd, SIOCSIFFLAGS, &ifr) < 0) {
            ERROR(strerror(errno));
            close(sd);

            return (-1);
        }
    }

    close(sd);
    return (0);
}

/*
 * Reading network ifaces hw-MAC address. 
 */
static int
iface_get_mac_address(void)
{
    eth_addr_t mac;
    eth_t *if_eth;
    int i;
	
    if ((if_eth = eth_open(dev.dev)) == NULL) {
        ERROR(strerror(errno));
		
        return (-1);
    }
	
    if (eth_get(if_eth, &mac) < 0) {
        ERROR(strerror(errno));
        eth_close(if_eth);

        return (-1);
    }
	
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        dev.dev_mac.octet[i] = mac.data[i];
    }

    eth_close(if_eth);

    return (0);
}

/*
 * Checks and saves IPv4 and Netmask network adresses.
 */
static int 
iface_get_inet4_addresses(void)
{
    char errbuf_lnet[LIBNET_ERRBUF_SIZE], errbuf_pcap[PCAP_ERRBUF_SIZE];
    libnet_t *lnet;
    bpf_u_int32 network;
    int ret, ret2, state = 0;
	
    /* 
     * Get netmask and IPv4 addresses.
     * Case of errors, it waits:
     *	- running iface
     *	- IPv4 assigned
     *	- online iface.
     */
    while (1) {
        dev.dev_netmask.s_addr = 0;
		
        if (pcap_lookupnet(dev.dev, &network, 
            &(dev.dev_netmask.s_addr), errbuf_pcap) < 0) {
            if (dif == IFACE_LIST) {
                return (0);
            } else {
                if (errno == EADDRNOTAVAIL) {
                    /*
                     * Use the state for one first WARNING print.
                     */
                    if (state == 0) {
                        aprintf(stdout, 1, "WARNING: %s\n", errbuf_pcap);
						
                        if (dinspec == INSPEC_NULL) {
                            exit(EXIT_FAILURE);
                        }
						
                        state = 1;
                    }
                    continue;
                } else {
                    if (dif != IFACE_AUTO) {
                        ERROR(errbuf_pcap);
                    }
					
                    return (-1);
                }
            }
        } else {
            /* Checks iface running.
             * Return:
             *	-1: Error
             *	 0: iface running
             *	 1: iface is not running.
             */
            if ((ret = iface_check_running()) < 0) {
                return (-1);
            } 
            /*
             * iface running.
             */
            else if (ret == 0) {
                /*
                 * Check iface online with 
                 * first packet received.
                 */
                if (dif != IFACE_LIST && dinspec != INSPEC_NULL) {
                    aprintf(stdout, 1, "WAIT LINK on %s...\n", 
                            dev.dev);
					
                    while (1) {
                        /*
                         * Check iface online.
                         * Return:
                         *  -1: Error
                         *   0: Online
                         *   1: Offline
                         */
                        if ((ret2 = iface_check_online()) < 0) {
                            return (-1);
                        } else if (ret2 == 1) {
                            sleep(1);
                            continue;
                        } else {
                            break;
                        }
                    }
                }
				
                /* 
                 * Get IPv4 address.
                 */
                if ((lnet = libnet_init(LIBNET_LINK, dev.dev, 
                    errbuf_lnet)) == NULL) {
                    if (dif == IFACE_LIST) {
                        return (0);
                    } else { 
                        ERROR(errbuf_lnet);

                        return (-1);
                    }
                }
			
                dev.dev_inet4.s_addr = 0;
			
                if ((dev.dev_inet4.s_addr = libnet_get_ipaddr4(lnet)) == -1) {
                    ERROR(libnet_geterror(lnet));

                    return (-1);	
                }
			
                libnet_destroy(lnet);
                break;
            }
			
            /*
             * iface is not running.
             */
        }
		
        /*
         * Check each 1 second.
         */
        sleep(1);
    }
	
    if (dinspec == INSPEC_NULL) {
        aprintf(stdout, 0, "DEV = <%s>\n", dev.dev);
        aprintf(stdout, 0, "HW = <%s>\n", ether_ntoa(&(dev.dev_mac)));
        aprintf(stdout, 0, "IP = <%s>\n", inet_ntoa(dev.dev_inet4));
    
        switch (dif) {
        case (IFACE_MANUAL):
        case (IFACE_AUTO):
            aprintf(stdout, 0, "\n");
            break;

        case (IFACE_LIST):
        case (IFACE_NULL):
            break;
        } 
    }
	
    return (0);
}

/*
 * Prints network ifaces informations.
 * For SARPI and DARPI.
 */
static void 
iface_info_print(void)
{
	struct tm tm_cur;
    time_t time_cur;

	time_cur = time(NULL);
	tm_cur = *(struct tm *) localtime(&time_cur);
		
    switch (dinspec) {
    case (INSPEC_SARPI):
        aprintf(stdout, 1, "SARPI on\n");
        break;
			
    case (INSPEC_DARPI):
        aprintf(stdout, 1, "DARPI on\n");
        break;
            
    case (INSPEC_HARPI):
        aprintf(stdout, 1, "HARPI on\n");
        break;
		
    case (INSPEC_NULL):
        break;
    }

    aprintf(stdout, 0, "\t DATE = <%02d/%02d/%04d>\n",
            tm_cur.tm_mon + 1, tm_cur.tm_mday, tm_cur.tm_year + 1900);
    aprintf(stdout, 0, "\t DEV = <%s>\n ", dev.dev);
    aprintf(stdout, 0, "\t HW = <%s>\n ", ether_ntoa(&(dev.dev_mac)));
    aprintf(stdout, 0, "\t IP = <%s>\n", inet_ntoa(dev.dev_inet4));
}

/********************
 * ARP Cache handler:
 ********************/

/*
 * Open ARP cache.
 */
static arp_t *
arp_cache_open(void)
{
    arp_t *arp;
	
    if ((arp = arp_open()) == NULL) {
        ERROR(strerror(errno));
        
        return (NULL);
    }
	
    return (arp);
}

/*
 * Close ARP cache.
 */
static void
arp_cache_close(arp_t *arp)
{
	
    arp_close(arp);
}

/*
 * Adds ARP cache entry.
 */
static int
arp_cache_add(char *arg)
{
    struct arp_entry entry;
    char c_mac[18], c_ip[16];
    arp_t *arp;
	
    if ((arp = arp_cache_open()) == NULL) {
    return (-1);
    }	

    sscanf(arg, "%15s %17s", c_ip, c_mac);
    c_mac[sizeof(char) * strlen(c_mac)] = '\0';
    c_ip[sizeof(char) * strlen(c_ip)] = '\0'; 
	
    if (addr_aton(c_mac, &entry.arp_ha) < 0) {
        ERROR(strerror(errno));
        arp_cache_close(arp);
		
        return (-1);
    }
	
    if (addr_aton(c_ip, &entry.arp_pa) < 0) {
        ERROR(strerror(errno));	
        arp_cache_close(arp);
		
        return (-1);
    }
	
    arp_add(arp, &entry);
	
    arp_cache_close(arp);
	
    return (0);
}

/*
 * Search entry in ARP cache, if is found it will delete. 
 */
static int
arp_cache_del(char *arg)
{
    struct arp_entry entry;
    arp_t *arp;
    int i;
	
    if ((arp = arp_cache_open()) == NULL) {
        return (-1);
    }
	
    /* 
     * Read ARP cache. 
     */
    if (arp_loop(arp, arp_cache_list_create, NULL) < 0) {
        arp_cache_close(arp);
		
        return (-1);
    }
	
    /* 
     * Search IPv4 in ARP Cache.
     */
    TAILQ_FOREACH(arp_cache_pos, &arp_cache_head, entries) {
        if (strcmp(arg, inet_ntoa(arp_cache_pos->ac_ip)) == 0) { 
            for (i = 0; i < ETHER_ADDR_LEN; i++) {
                entry.arp_ha.addr_eth.data[i] = arp_cache_pos->ac_mac.octet[i];
            }

            if (addr_aton(inet_ntoa(arp_cache_pos->ac_ip), &entry.arp_pa) < 0) {
                ERROR(strerror(errno));
                arp_cache_list_destroy();               
                arp_cache_close(arp);

                return (-1);
            }
		
            arp_delete(arp, &entry);
			
            arp_cache_list_destroy();               
            arp_cache_close(arp);

            return (0);
        }
    }

    /*
     * Entry not found!
     */
    arp_cache_list_destroy();
    arp_cache_close(arp);
    
    return (1);
}

/*
 * Delete all found entries in the ARP 
 * cache reading ARP cache tail.
 */
static int
arp_cache_del_all(void)
{
    struct arp_entry entry;
    arp_t *arp;
    int i;
	
    if ((arp = arp_cache_open()) == NULL) {
        return (-1);
    }
	
    /* 
     * Read ARP cache. 
     */
    if (arp_loop(arp, arp_cache_list_create, NULL) < 0) {
        arp_cache_close(arp);
		
        return (-1);
    }
	
    TAILQ_FOREACH(arp_cache_pos, &arp_cache_head, entries) {
        for (i = 0; i < ETHER_ADDR_LEN; i++) {
            entry.arp_ha.addr_eth.data[i] = arp_cache_pos->ac_mac.octet[i];
        }
		
        if (addr_aton(inet_ntoa(arp_cache_pos->ac_ip), &entry.arp_pa) < 0) {
            ERROR(strerror(errno));
            arp_cache_list_destroy();               
            arp_cache_close(arp);
			
            return (-1);
        }
		
        arp_delete(arp, &entry);
    }
	
    arp_cache_list_destroy();
    arp_cache_close(arp);
	
    return (0);
}

/*
 * Create ARP cache tail using one entry or it adds simply a new entry.
 */
static int
arp_cache_list_create(const struct arp_entry *entry, void *arg)
{
    struct ether_addr mac;
    struct in_addr ip;
    register int i;

    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        mac.octet[i] = entry->arp_ha.addr_eth.data[i];
    }

    ip.s_addr = entry->arp_pa.addr_ip;
	
    if (arp_cache_begin == NULL) { 
        TAILQ_INIT(&arp_cache_head);
	
        if ((arp_cache_begin = malloc(sizeof(struct arp_cache))) == NULL) { 
            ERROR(strerror(errno));

            return (-1);
        }
		
        memcpy(&arp_cache_begin->ac_mac, &mac, sizeof(mac));
        memcpy(&arp_cache_begin->ac_ip, &ip, sizeof(ip));
        TAILQ_INSERT_HEAD(&arp_cache_head, arp_cache_begin, entries);
    } else {
        if ((arp_cache_next = malloc(sizeof(struct arp_cache))) == NULL) { 
            ERROR(strerror(errno));

            return (-1);
        }
		
        memcpy(&arp_cache_next->ac_mac, &mac, sizeof(mac));
        memcpy(&arp_cache_next->ac_ip, &ip, sizeof(ip));
        TAILQ_INSERT_TAIL(&arp_cache_head, arp_cache_next, entries);
    }
	
    return (0);
}

/*
 * Destroy ARP cache tail.
 */
static void
arp_cache_list_destroy(void)
{

    while (TAILQ_EMPTY(&arp_cache_head) == 0) {
        arp_cache_pos = TAILQ_FIRST(&arp_cache_head);
		
        TAILQ_REMOVE(&arp_cache_head, arp_cache_pos, entries);
        free(arp_cache_pos);
    }
}


/******************
 * SARPI handler: *
 ******************/

/*
 * Sets ARP cache timeout for automatic update.
 */
static int
sarpi_set_timeout(char *timeout)
{
    int val = atoi(timeout);
	
    /*
     * Don't accept timeout < 0.
     */
    if (val < 0) {
        aprintf(stderr, 0, 
                "ERROR: SARPI timeout %d minuts out of the range.\n\n", val);
		
        return (-1);
    }
	
    sarpi_timeout = val;
	
    return (0);
}

/*
 * SARPI manager signal handler.
 */
static void
sarpi_manager_thread_sigusr1(int sig)
{
	
    sarpi_cache_list_destroy();
    pthread_exit((void *) 0);
}

/*
 * Handles SARPI through two thread for parallelism:
 *  - 1:    Update automatically the ARP cache
 *  - 2:    Works in soft real time, in other words it 
 *          listens to the inbound/outbound arp packets.	
 */
static void *
sarpi_manager_thread(void *arg)
{
    struct sigaction saction;
	
#ifdef NETBSD
    saction.sa_flags = 0;
#endif
    saction.sa_handler = sarpi_manager_thread_sigusr1;
	
    if (sigaction(SIGUSR1, &saction, NULL) < 0) {
        ERROR(strerror(errno));
		
        pthread_exit((void *) -1);
    }
	
    /*
     * Iface work.
     */
    if (iface_manager() < 0) {
        pthread_exit((void *) -1);
    }
	
    if (iface_check_uplink() < 0) {
        pthread_exit((void *) -1);
    }
	
    iface_info_print();

    /* 
     * PID Parent CPU Scheduling. 
     */
    if (task_mode_cpu_priority(PRIO_PROCESS, getpid(), cpu_priority) < 0) {
        pthread_exit((void *) -1);
    }
	
    /* 
     * Delete all ARP Cache entries (Possible entries poisoned). 
     */
    if (arp_cache_del_all() < 0) {
        pthread_exit((void *) -1);
    }
	
    pthread_rwlock_init(&rlock, NULL);
    pthread_rwlock_init(&wlock, NULL);

    /* 
     * ARP Cache entries protected from file. 
     */
    if (sarpi_cache_file_restore() < 0) {
        exit(-1);
    }
	
    pthread_attr_init(&detach_attr);
    pthread_attr_setdetachstate(&detach_attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setschedpolicy(&detach_attr, SCHED_RR);
	
    /*
     * Thread 4 detached, update automatically the ARP cache. 
     */
    if (pthread_create(&thread[3], &detach_attr, 
        sarpi_cache_list_refresh_thread, (void *) NULL) != 0) {
        ERROR(strerror(errno));
        sarpi_cache_list_destroy();
		
        pthread_exit((void *) -1);
    }

    /*
     * Thread 5 detached, realtime inbound/outbound work.
     */
    if (sarpi_realtime() < 0) {
        sarpi_cache_list_destroy();
		
        pthread_exit((void *) -1);
    }

    pthread_exit((void *) 0);
}

/*
 * SARPI Realtime, process ARP reply 
 * inbound/outbound ARP packets.
 */
static int
sarpi_realtime(void)
{
	
    pthread_attr_init(&detach_attr);
    pthread_attr_setdetachstate(&detach_attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setschedpolicy(&detach_attr, SCHED_RR);

    /*
     * Thread 5 detached, Works in soft real time, in other 
     * words it listens to the inbound/outbound ARP packets.
     */
    if (pthread_create(&thread[4], &detach_attr, sarpi_realtime_thread, 
        (void *) NULL) != 0) {
        ERROR(strerror(errno));
	
        return (-1);
    }
	
    pthread_attr_destroy(&detach_attr);
	
    return (0);
}

/*
 * SARPI realtime signal handler.
 */
static void
sarpi_realtime_thread_sigusr1(int sig)
{
	
    pthread_exit((void *) 0);
}

/*
 * Use thread for non blocking to pcap_loop().
 */
static void *
sarpi_realtime_thread(void *arg)
{
    struct sigaction saction;
    pcap_t *pcap;
	
#ifdef NETBSD
    saction.sa_flags = 0;
#endif
    saction.sa_handler = sarpi_realtime_thread_sigusr1;
	
    if (sigaction(SIGUSR1, &saction, NULL) < 0) {
        ERROR(strerror(errno));
		
        pthread_exit((void *) -1);
    }
	
    if ((pcap = sarpi_realtime_open_packets()) == NULL) {
        pthread_exit((void *) -1);
    }

    while (1) {
        if (pcap_loop(pcap, 1, sarpi_realtime_read_packets, NULL) < 0) {
            ERROR(pcap_geterr(pcap));
            sarpi_realtime_close_packets(pcap);

            pthread_exit((void *) -1);
        }
    }

    sarpi_realtime_close_packets(pcap);

    pthread_exit((void *) 0);
}

/*
 * Open pcap file descriptor.
 */
static pcap_t *
sarpi_realtime_open_packets(void)
{
    struct bpf_program compiled_filter;
    char errbuf[PCAP_ERRBUF_SIZE], *filter = "arp";
    pcap_t *pcap;
#ifndef LINUX
    unsigned int op = 1;
#endif

    if ((pcap = pcap_open_live(dev.dev, BUFSIZ, 0, 0, errbuf)) == NULL) {
        ERROR(errbuf);
		
        return (NULL);
    }

#ifndef LINUX
    /* 
     * BSD, differently from linux does not 
     * support automatic socket soft real time 
     * (Linux Socket Filter). 
     * Therefore on BSD platform it's necessary 
     * to use this I/O Control.
     */
    if (ioctl(pcap_fileno(pcap), BIOCIMMEDIATE, &op) < 0) {
        ERROR(strerror(errno));
		
        return (NULL);
    }
#endif

    if (pcap_compile(pcap, &compiled_filter, filter, 0, 
        dev.dev_netmask.s_addr) < 0) {
        ERROR(pcap_geterr(pcap));
        sarpi_realtime_close_packets(pcap);

        return (NULL);
    }
	
    if (pcap_setfilter(pcap, &compiled_filter) < 0) {
        ERROR(pcap_geterr(pcap));
        sarpi_realtime_close_packets(pcap);

        return (NULL);
    }	
	
    pcap_freecode(&compiled_filter);
    return (pcap);
}

/*
 * Close pcap file descriptor.
 */
static void
sarpi_realtime_close_packets(pcap_t *pcap)
{

    pcap_close(pcap);
}

/*
 * SARPI I/O
 * Read doc/SARPI.jpg algorithm.
 */
static void
sarpi_realtime_read_packets(unsigned char *arg, const struct pcap_pkthdr 
    *header, const unsigned char *packet)
{
    struct ether_addr src_mac, dst_mac;
    struct arp_header *arp_packet;
    char c_src_ip[16], c_src_mac[18], c_dst_ip[16], c_dst_mac[18], 
         c_ap_ip[16], entry[34];
    int i;

    /* 
     * ARP Packet. 
     */	
    arp_packet = (struct arp_header *) (packet + dev.dev_offset);

    /*
     * Convert the source MAC/IPv4 to string.
     */
    snprintf(c_src_ip, 16, "%d.%d.%d.%d", 
             arp_packet->ah_addresses.ar_spa[0], 
             arp_packet->ah_addresses.ar_spa[1],
             arp_packet->ah_addresses.ar_spa[2], 
             arp_packet->ah_addresses.ar_spa[3]);
		
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        src_mac.octet[i] = arp_packet->ah_addresses.ar_sha[i];
    }	
    strncpy(c_src_mac, ether_ntoa(&src_mac), sizeof(char) * 18);
    c_src_mac[sizeof(char) * strlen(c_src_mac)] = '\0';

    /*
     * Convert the destination MAC/IPv4 to string
     */
    snprintf(c_dst_ip, 16, "%d.%d.%d.%d", 
             arp_packet->ah_addresses.ar_tpa[0], 
             arp_packet->ah_addresses.ar_tpa[1],
             arp_packet->ah_addresses.ar_tpa[2], 
             arp_packet->ah_addresses.ar_tpa[3]);

    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        dst_mac.octet[i] = arp_packet->ah_addresses.ar_tha[i];
    }

    strncpy(c_dst_mac, ether_ntoa(&dst_mac), sizeof(char) * 18);
    c_dst_mac[sizeof(char) * strlen(c_dst_mac)] = '\0';

    /* 
     * In request, possible source address poisoned.
     * In reply, possible ARP Gratuitous for ARP poisoning.
     */
    if (ntohs(arp_packet->ah_header.ar_op) == ARP_OP_REQUEST) {
        /* 
         * Check if it is a broadcast address. 
         */
        if (strcmp(c_src_ip, inet_ntoa(dev.dev_inet4)) != 0 &&
            strcmp(c_dst_ip, inet_ntoa(dev.dev_inet4)) != 0 &&
            strcmp(c_src_ip, c_dst_ip) == 0) {
            /* 
             * Search ARP reply source in SARPI (ARP cache) entries. 
             */
            TAILQ_FOREACH(sarpi_cache_pos, &sarpi_cache_head, entries) {
                /*
                 * Convert MAC/IPv4 to string form.
                 */
                memset(c_ap_ip, '\0', sizeof(char) * 16);
                strncpy(c_ap_ip, inet_ntoa(sarpi_cache_pos->sc_ip), 
                        sizeof(char) * 16);
                c_ap_ip[sizeof(char) * strlen(c_ap_ip)] = '\0';
                
                /* 
                 * In reply, possible ARP Gratuitous for ARP poisoning.
                 * Check if source is found in SARPI Cache. 
                 */
                if (strcmp(c_src_ip, c_ap_ip) == 0) {
                    /* 
                     * Source is Found! We reset static entry.
                     */
                    aprintf(stdout, 1, "ARP cache, REFRESH\n");
                    
                    /* 
                     * Refresh static ARP Cache entry. 
                     */
                    snprintf(entry, 34, "%15s %17s", 
                             inet_ntoa(sarpi_cache_pos->sc_ip),
                             ether_ntoa(&(sarpi_cache_pos->sc_mac)));
                    entry[strlen(entry)] = '\0';
					
                    if (arp_cache_del(c_src_ip) < 0) {
                        exit(EXIT_FAILURE);
                    }
                    
                    if (arp_cache_add(entry) < 0) {
                        exit(EXIT_FAILURE);
                    } 
					
                    aprintf(stdout, 0, "\t src HW = <%s>\n", 
                            ether_ntoa(&(sarpi_cache_pos->sc_mac)));
                    aprintf(stdout, 0, "\t src IP = <%s>\n", 
                            inet_ntoa(sarpi_cache_pos->sc_ip));
                    
                    return;
                }
            }
            
            /* 
             * Entry is not found in SARPI cache.
             * This entry is not protected by SARPI!
             * In request, possible source address poisoned.
             * In reply, possible ARP Gratuitous for ARP poisoning.
             */
            aprintf(stdout, 1, "ARP cache, IGNORE\n");
            aprintf(stdout, 0, "\t src HW = <%s>\n", c_src_mac);
            aprintf(stdout, 0, "\t src IP = <%s>\n", c_src_ip);
        }
    } else if (ntohs(arp_packet->ah_header.ar_op) == ARP_OP_REPLY) {
        /* 
         * Check if we are the destionation address. 
         */
        if (strcmp(c_dst_ip, inet_ntoa(dev.dev_inet4)) == 0 &&
            strcmp(c_dst_mac, ether_ntoa(&(dev.dev_mac))) == 0) {
            /* 
             * Search ARP reply source in SARPI (ARP cache) entries. 
             */
            TAILQ_FOREACH(sarpi_cache_pos, &sarpi_cache_head, entries) {
                /*
                 * Convert MAC/IPv4 to string form.
                 */
                memset(c_ap_ip, '\0', sizeof(char) * 16);
                strncpy(c_ap_ip, inet_ntoa(sarpi_cache_pos->sc_ip), 
                        sizeof(char) * 16);
                c_ap_ip[sizeof(char) * strlen(c_ap_ip)] = '\0';

                /* 
                 * In reply, possible ARP Gratuitous for ARP poisoning.
                 * Check if source is found in SARPI Cache. 
                 */
                if (strcmp(c_src_ip, c_ap_ip) == 0) {
                    /* 
                     * Source is Found! We reset static entry.
                     */
                    aprintf(stdout, 1, "ARP cache, REFRESH\n");

                    /* 
                     * Refresh static ARP Cache entry. 
                     */
                    snprintf(entry, 34, "%15s %17s", 
                             inet_ntoa(sarpi_cache_pos->sc_ip),
                             ether_ntoa(&(sarpi_cache_pos->sc_mac)));
                    entry[strlen(entry)] = '\0';
					
                    if (arp_cache_del(c_src_ip) < 0) {
                        exit(EXIT_FAILURE);
                    }
                    
                    if (arp_cache_add(entry) < 0) {
                        exit(EXIT_FAILURE);
                    } 
					
                    aprintf(stdout, 0, "\t src HW = <%s>\n", 
                            ether_ntoa(&(sarpi_cache_pos->sc_mac)));
                    aprintf(stdout, 0, "\t src IP = <%s>\n", 
                            inet_ntoa(sarpi_cache_pos->sc_ip));
	
                    return;
                }
            }

            /* 
             * Entry is not found in SARPI cache.
             * This entry is not protected by SARPI!
             * In request, possible source address poisoned.
             * In reply, possible ARP Gratuitous for ARP poisoning.
             */
            aprintf(stdout, 1, "ARP cache, IGNORE\n");
            aprintf(stdout, 0, "\t src HW = <%s>\n", c_src_mac);
            aprintf(stdout, 0, "\t src IP = <%s>\n", c_src_ip);
        } 
        /* 
         * Check if we are the source address. 
         */
        else if (strcmp(c_src_ip, inet_ntoa(dev.dev_inet4)) == 0 &&
                 strcmp(c_src_mac, ether_ntoa(&(dev.dev_mac))) == 0) {
            /* 
             * Search ARP request destination in SARPI (ARP cache) entries. 
             */
            TAILQ_FOREACH(sarpi_cache_pos, &sarpi_cache_head, entries) {
                /*
                 * Convert MAC/IPv4 to string form.
                 */
                memset(c_ap_ip, '\0', sizeof(char) * 16);
                strncpy(c_ap_ip, inet_ntoa(sarpi_cache_pos->sc_ip), 
                        sizeof(char) * 16);
                c_ap_ip[sizeof(char) * strlen(c_ap_ip)] = '\0';
                
                /* 
                 * In request, possible source address poisoned.
                 * Check if destination is found in SARPI Cache. 
                 */
                if (strcmp(c_dst_ip, c_ap_ip) == 0) {
                    /* 
                     * Source is Found! We reset static entry.
                     */
                    aprintf(stdout, 1, "ARP cache, REFRESH\n");
                    
                    /* 
                     * Refresh static ARP Cache entry. 
                     */
                    snprintf(entry, 34, "%15s %17s", 
                             inet_ntoa(sarpi_cache_pos->sc_ip),
                             ether_ntoa(&(sarpi_cache_pos->sc_mac)));
                    entry[strlen(entry)] = '\0';
					
                    if (arp_cache_del(c_dst_ip) < 0) {
                        exit(EXIT_FAILURE);
                    } 
                    
                    if (arp_cache_add(entry) < 0) {
                        exit(EXIT_FAILURE);
                    } 
					
                    aprintf(stdout, 0, "\t src HW = <%s>\n", 
                            ether_ntoa(&(sarpi_cache_pos->sc_mac)));
                    aprintf(stdout, 0, "\t src IP = <%s>\n", 
                            inet_ntoa(sarpi_cache_pos->sc_ip));
                    
                    return;
                }
            }
            
            /* 
             * Entry is not found in SARPI cache.
             * This entry is not protected by SARPI!
             * In request, possible source address poisoned.
             * In reply, possible ARP Gratuitous for ARP poisoning.
             */
            aprintf(stdout, 1, "ARP cache, IGNORE\n");
            aprintf(stdout, 0, "\t src HW = <%s>\n", c_dst_mac);
            aprintf(stdout, 0, "\t src IP = <%s>\n", c_dst_ip);
        }         
    }
}

/*
 * Sets static ARP cache entries from file.
 * Parsing of example:
 *
 * # Example of sarpi.cache
 * #
 * 192.168.1.1 aa:bb:cc:dd:ee:ff
 * ...
 */
static int
sarpi_cache_file_restore(void)
{
    struct addr aip, amac;
    struct arp_entry entry;
    char buf[100], ip[16], mac[18];
    FILE *fd;
    int i;
	
    if ((fd = fopen(sarpi_cache_file, "r")) == NULL) {
        aprintf(stderr, 0, "ERROR: Configure static " \
                "ARP Cache entries in %s!\n\n", sarpi_cache_file);
		
        return (-1);
    }
	
    aprintf(stdout, 0, "\t CACHE = <%s>\n", sarpi_cache_file);
	
    for (i = 1; feof(fd) == 0; i++) {
        if (fgets(buf, 100, fd) == NULL) {
            break;
        }
		
        /*
         * Comment or new line.
         */
        if (buf[0] == '#' || buf[0] == '\n') {
            continue;
        }
		
        /*
         * Space line and Tab line with no entry.
         */
        if (buf[0] == ' ' || buf[0] == '\t') {
            if (buf[1] == '#' || buf[1] == '\n' || 
                buf[1] == ' ' || buf[1] == '\t')
                continue;
        }
		
        memset(ip, '\0', 16);
        memset(mac, '\0', 18);
	
        sscanf(buf, "%15s %17s", ip, mac);
        
        if (addr_pton(ip, &aip) < 0) {
            aprintf(stderr, 0, "ERROR: " 
                    "It is not IPv4. Reconfigure %s:%d line!\n\n",
                    sarpi_cache_file, i);
            fclose(fd);
			
            return (-1);
        } else if (addr_pton(mac, &amac) < 0) {
            aprintf(stderr, 0, "ERROR: "
                    "It is not Mac-hw. Reconfigure %s:%d line!\n\n",
                    sarpi_cache_file, i);
            fclose(fd);
			
            return (-1);
        }
	
        memcpy(&(entry.arp_pa), &aip, sizeof(aip));
        memcpy(&(entry.arp_ha), &amac, sizeof(amac));
		
        if (sarpi_cache_list_create(&entry, NULL) < 0) {
            fclose(fd);
			
            return (-1);
        }   
    }
	
    fclose(fd);
    return (0);
}

/*
 * Adds SARPI cache tail.
 */
static int
sarpi_cache_list_create(const struct arp_entry *entry, void *arg)
{
    struct ether_addr mac;
    struct in_addr ip;
    int i;
	
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        mac.octet[i] = entry->arp_ha.addr_eth.data[i];
    }
	
    ip.s_addr = entry->arp_pa.addr_ip;
	
    pthread_rwlock_wrlock(&wlock);
	
    if (sarpi_cache_begin == NULL) { 
        TAILQ_INIT(&sarpi_cache_head);
		
        if ((sarpi_cache_begin = malloc(sizeof(struct arp_cache))) == NULL) { 
            ERROR(strerror(errno));		
			
            pthread_rwlock_unlock(&wlock);
			
            return (-1);
        }
		
        memcpy(&sarpi_cache_begin->sc_mac, &mac, sizeof(mac));
        memcpy(&sarpi_cache_begin->sc_ip, &ip, sizeof(ip));
        TAILQ_INSERT_HEAD(&sarpi_cache_head, sarpi_cache_begin, entries);
        
        pthread_rwlock_unlock(&wlock);
		
        return (0);
    } 
	
    if ((sarpi_cache_next = malloc(sizeof(struct arp_cache))) == NULL) { 
        ERROR(strerror(errno));
		
        pthread_rwlock_unlock(&wlock);
		
        return (-1);
    }
	
    memcpy(&sarpi_cache_next->sc_mac, &mac, sizeof(mac));
    memcpy(&sarpi_cache_next->sc_ip, &ip, sizeof(ip));
    TAILQ_INSERT_TAIL(&sarpi_cache_head, sarpi_cache_next, entries);
    
    pthread_rwlock_unlock(&wlock);
	
    return (0);
}

/* 
 * SARPI cache list signal handler.
 */
static void
sarpi_cache_list_refresh_thread_sigusr1(int sig)
{
	
    pthread_exit((void *) 0);
}

/*
 * During every timeout it updates SARPI 
 * cache static entries in ARP cache.
 */
static void * 
sarpi_cache_list_refresh_thread(void *arg)
{
    struct sigaction saction;
    char entry[34];
#ifdef NETBSD
    int ret = 0;
#endif
	
#ifdef NETBSD
    saction.sa_flags = 0;
#endif
    saction.sa_handler = sarpi_cache_list_refresh_thread_sigusr1;
	
    if (sigaction(SIGUSR1, &saction, NULL) < 0) {
        ERROR(strerror(errno));
		
        pthread_exit((void *) -1);
    }
	
    for (;;) {
        /* 
         * Sleep for thread suspend.
         */

        /*
         * Convert by seconds to minuts.
         */
#ifdef NETBSD
        if ((ret = sleep(sarpi_timeout * 60)) > 0) {
#else
        if (sleep(sarpi_timeout * 60) > 0) {
#endif  
            ERROR(strerror(errno));
				
            pthread_exit((void *) -1);
        }
			
#ifdef NETBSD
        /*
         * For SIGINT, SIGTERM, SIGQUIT,
         * It exited.
         */
			
        if (ret != 0) {
            pthread_exit((void *) -1);
        }
#endif
			
        aprintf(stdout, 1, "ARP cache, UPDATE\n");
			
        pthread_rwlock_rdlock(&rlock);
        pthread_rwlock_wrlock(&wlock);
            
        TAILQ_FOREACH(sarpi_cache_pos, &sarpi_cache_head, entries) {
            /* 
             * Refresh ARP Cache entries. 
             */
            
            snprintf(entry, 34, "%15s %17s", 
                     inet_ntoa(sarpi_cache_pos->sc_ip),
                     ether_ntoa(&(sarpi_cache_pos->sc_mac)));
            entry[strlen(entry)] = '\0';
				
            if (arp_cache_del(inet_ntoa(sarpi_cache_pos->sc_ip)) < 0) {
                pthread_rwlock_unlock(&wlock);
                pthread_rwlock_unlock(&rlock);
                
                pthread_exit((void *) -1);
            }
            
            if (arp_cache_add(entry) < 0) {
                pthread_rwlock_unlock(&wlock);
                pthread_rwlock_unlock(&rlock);
					
                pthread_exit((void *) -1);
            }			
			
            aprintf(stdout, 0, "\t src HW = <%s>\n",
                    ether_ntoa(&(sarpi_cache_pos->sc_mac)));
            aprintf(stdout, 0, "\t src IP = <%s>\n",
                    inet_ntoa(sarpi_cache_pos->sc_ip));
        }
			
        pthread_rwlock_unlock(&wlock);
        pthread_rwlock_unlock(&rlock);
    }
		
    pthread_exit((void *) 0);
}
	
/*
 * Destroy SARPI cache tail.
 */
static void
sarpi_cache_list_destroy(void)
{
		
    pthread_rwlock_rdlock(&rlock);
		
    while (TAILQ_EMPTY(&sarpi_cache_head) == 0) {
        pthread_rwlock_wrlock(&wlock);
			
        sarpi_cache_pos = TAILQ_FIRST(&sarpi_cache_head);
			
        TAILQ_REMOVE(&sarpi_cache_head, sarpi_cache_pos, entries);
        free(sarpi_cache_pos);
			
        pthread_rwlock_unlock(&wlock);
    }
		
    pthread_rwlock_unlock(&rlock);
}	
	
/******************
 * DARPI handler: *
 ******************/

/*
 * Set DARPI Cache entry timeout.
 */
static int
darpi_set_timeout(char *timeout)
{
    int val = atoi(timeout);
	
    /*
     * Don't accept timeout < 0.
     */
    if (val < 0) {
        aprintf(stderr, 0, 
                "ERROR: DARPI timeout %d seconds out of the range.\n\n", val);
		
        return (-1);
    }
	
    darpi_timeout = val;
	
    return (0);
}

/*
 * DARPI manager signal handler.
 */
static void
darpi_manager_thread_sigusr1(int sig)
{
	
    darpi_cache1_list_destroy();
    darpi_cache2_list_destroy();
    darpi_cache3_list_destroy();
    pthread_exit((void *) 0);
}
	
/* 
 * Handles DARPI, delete all found entries 
 * in the ARP cache to delete some poisoned 
 * hosts then it starts realtime execution
 * to reads the packets:
 *  - ARP request
 *  - ARP reply.
 */
static void *
darpi_manager_thread(void *arg)
{
    struct sigaction saction;
	
#ifdef NETBSD
    saction.sa_flags = 0;
#endif
    saction.sa_handler = darpi_manager_thread_sigusr1;
	
    if (sigaction(SIGUSR1, &saction, NULL) < 0) {
        ERROR(strerror(errno));
		
        pthread_exit((void *) -1);
    }
	
    /*
     * Iface work.
     */
    if (iface_manager() < 0) {
        pthread_exit((void *) -1);
    }
	
    if (iface_check_uplink() < 0) {
        pthread_exit((void *) -1);
    }
	
    iface_info_print();

    /* 
     * PID CPU Scheduling.
     */
    if (task_mode_cpu_priority(PRIO_PROCESS, getpid(), cpu_priority) < 0) {
        pthread_exit((void *) -1);
    }

    /* 
     * Delete all ARP Cache entries (Possible entries poisoned). 
     */
    if (arp_cache_del_all() < 0) {
        pthread_exit((void *) -1);
    }

    /*
     * Thread 4 detached, inbound/outbound work.
     */
    if (darpi_realtime() < 0) {
        pthread_exit((void *) -1);
    }

    pthread_exit((void *) 0);
}

/*
 * DARPI Realtime execution, process all 
 * inbound/outbound ARP packets.
 */
static int
darpi_realtime(void)
{
	
    pthread_attr_init(&detach_attr);
    pthread_attr_setdetachstate(&detach_attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setschedpolicy(&detach_attr, SCHED_RR);

    /* 
     * Thread 4 detached, realtime inbound/outbound work.
     */
    if (pthread_create(&thread[3], &detach_attr, darpi_realtime_thread, 
        (void *) NULL) != 0) {
        ERROR(strerror(errno));

        return (-1);
    }
	
    pthread_attr_destroy(&detach_attr);
    
    pthread_attr_init(&detach_attr);
    pthread_attr_setdetachstate(&detach_attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setschedpolicy(&detach_attr, SCHED_RR);
    
    /* 
     * Thread 5 detached, Check each DARPI Cache 1 entry with 
     * timeout, possible host doesn't present in the network.
     */
    pthread_create(&thread[4], &detach_attr, 
                   darpi_cache1_list_check_thread, (void *) NULL);
    
    /* 
     * Thread 6 detached, Check each DARPI Cache 2 entry with 
     * timeout, possible host doesn't present in the network.
     */
    pthread_create(&thread[5], &detach_attr, 
                   darpi_cache2_list_check_thread, (void *) NULL);
    
    /* 
     * Thread 7 detached, Check each DARPI Cache 3 entry with 
     * timeout, possible host doesn't present in the network.
     */
    pthread_create(&thread[6], &detach_attr, 
                   darpi_cache3_list_check_thread, (void *) NULL);
    
    pthread_attr_destroy(&detach_attr);
    
    darpi_cache1_list_destroy();
	darpi_cache2_list_destroy();
    darpi_cache3_list_destroy();
    
    return (0);
}

/*
 * DARPI realtime signal handler.
 */
static void
darpi_realtime_thread_sigusr1(int sig)
{
		
    pthread_exit((void *) 0);
}
	
/*
 * Use thread for non blocking to pcap_loop().
 */
static void *
darpi_realtime_thread(void *arg)
{
    struct sigaction saction;
    pcap_t *pcap;
	
#ifdef NETBSD
    saction.sa_flags = 0;
#endif
    saction.sa_handler = darpi_realtime_thread_sigusr1;

    if (sigaction(SIGUSR1, &saction, NULL) < 0) {
        ERROR(strerror(errno));
		
        pthread_exit((void *) -1);
    }

    if ((pcap = darpi_realtime_open_packets()) == NULL) {
        pthread_exit((void *) -1);
    }
	
    pthread_rwlock_init(&rlock2, NULL);
    pthread_rwlock_init(&wlock2, NULL);
    pthread_rwlock_init(&rlock3, NULL);
    pthread_rwlock_init(&wlock3, NULL);
    pthread_rwlock_init(&rlock4, NULL);
    pthread_rwlock_init(&wlock4, NULL);
    
    while (1) {
        if (pcap_loop(pcap, 1, darpi_realtime_read_packets, NULL) < 0) {
            ERROR(pcap_geterr(pcap));

            pthread_rwlock_destroy(&wlock2);
            pthread_rwlock_destroy(&rlock2);
            pthread_rwlock_destroy(&wlock3);
            pthread_rwlock_destroy(&rlock3);
            pthread_rwlock_destroy(&wlock4);
            pthread_rwlock_destroy(&rlock4);
            darpi_realtime_close_packets(pcap);
			
            pthread_exit((void *) -1);
        }
    }

    pthread_rwlock_destroy(&wlock2);
    pthread_rwlock_destroy(&rlock2);
    pthread_rwlock_destroy(&wlock3);
    pthread_rwlock_destroy(&rlock3);
    pthread_rwlock_destroy(&wlock4);
    pthread_rwlock_destroy(&rlock4);
    darpi_realtime_close_packets(pcap);
	
    pthread_exit((void *) 0);
}

/*
 * Open pcap file descriptor.
 */
static pcap_t *
darpi_realtime_open_packets(void)
{
    struct bpf_program compiled_filter;
    char errbuf[PCAP_ERRBUF_SIZE], *filter = "arp";
    pcap_t *pcap;
#ifndef LINUX
    unsigned int op = 1;
#endif
	
    if ((pcap = pcap_open_live(dev.dev, BUFSIZ, 0, 0, errbuf)) == NULL) {
        ERROR(errbuf);

        return (NULL);
    }

#ifndef LINUX
    /* 
     * BSD, differently from linux does not 
     * support automatic socket soft real time 
     * (Linux Socket Filter). 
     * Therefore on BSD platform it's necessary 
     * to use this I/O Control.
     */
    if (ioctl(pcap_fileno(pcap), BIOCIMMEDIATE, &op) < 0) {
        ERROR(strerror(errno));

        return (NULL);
    }
#endif

    if (pcap_compile(pcap, &compiled_filter, filter, 0, 
        dev.dev_netmask.s_addr) < 0) {
        ERROR(pcap_geterr(pcap));
        darpi_realtime_close_packets(pcap);

        return (NULL);
    }
	
    if (pcap_setfilter(pcap, &compiled_filter) < 0) {
        ERROR(pcap_geterr(pcap));
        darpi_realtime_close_packets(pcap);

        return (NULL);
    }	
	
    pcap_freecode(&compiled_filter);
    return (pcap);
}

/*
 * Close pcap file descriptor.
 */
static void
darpi_realtime_close_packets(pcap_t *pcap)
{

    pcap_close(pcap);
}

/*
 * DARPI I/O
 * Read doc/DARPI.jpg algorithm.
 */
static void
darpi_realtime_read_packets(unsigned char *arg, const struct pcap_pkthdr 
    *header, const unsigned char *packet)
{
    struct ether_addr src_mac, dst_mac;
    struct in_addr src_ip, dst_ip;
    struct arp_header *arp_packet;
    char c_src_ip[16], c_src_mac[18], c_dst_ip[16], c_dst_mac[18], entry[34];
    int i, ret = 0;	

    /* 
     * ARP Packet.
     */
    arp_packet = (struct arp_header *) (packet + dev.dev_offset);

    /*
     * Convert source MAC/IPv4 string.
     */
    snprintf(c_src_ip, 16, "%d.%d.%d.%d", 
             arp_packet->ah_addresses.ar_spa[0], 
             arp_packet->ah_addresses.ar_spa[1],
             arp_packet->ah_addresses.ar_spa[2], 
             arp_packet->ah_addresses.ar_spa[3]);
    inet_aton(c_src_ip, &src_ip);
    
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        src_mac.octet[i] = arp_packet->ah_addresses.ar_sha[i];
    }
    strncpy(c_src_mac, ether_ntoa(&src_mac), sizeof(char) * 18);
    c_src_mac[sizeof(char) * strlen(c_src_mac)] = '\0';

    /*
     * Convert destination MAC/IPv4 string.
     */
    snprintf(c_dst_ip, 16, "%d.%d.%d.%d", 
             arp_packet->ah_addresses.ar_tpa[0], 
             arp_packet->ah_addresses.ar_tpa[1],
             arp_packet->ah_addresses.ar_tpa[2], 
             arp_packet->ah_addresses.ar_tpa[3]);
    inet_aton(c_dst_ip, &dst_ip);

    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        dst_mac.octet[i] = arp_packet->ah_addresses.ar_tha[i];
    }
    strncpy(c_dst_mac, ether_ntoa(&dst_mac), sizeof(char) * 18);
    c_dst_mac[sizeof(char) * strlen(c_dst_mac)] = '\0';

    if (ntohs(arp_packet->ah_header.ar_op) == ARP_OP_REQUEST) {
        /* 
         * Check if it is a broadcast address. 
         */
        if (strcmp(c_src_ip, inet_ntoa(dev.dev_inet4)) != 0 &&
            strcmp(c_dst_ip, inet_ntoa(dev.dev_inet4)) != 0 &&
            strcmp(c_src_ip, c_dst_ip) == 0) {
            if (darpi_realtime_send_packet(&src_ip) < 0) {
				exit(EXIT_FAILURE);
            }
            
            if ((ret = arp_cache_del(c_src_ip)) < 0) {
                exit(EXIT_FAILURE);
            } else if (ret == 0) {
                aprintf(stdout, 1, "ARP cache, DENY\n");
                aprintf(stdout, 0, "\t src HW = <%s>\n", c_src_mac);
                aprintf(stdout, 0, "\t src IP = <%s>\n", c_src_ip);
            }
        }
        /* 
         * Check if we are the source address. 
         */
        else if (strcmp(c_src_mac, ether_ntoa(&(dev.dev_mac))) == 0 && 
                 strcmp(c_src_ip, inet_ntoa(dev.dev_inet4)) == 0) {
			
            /* 
             * DARPI 1 Cache Add/Refresh. 
             */
            if (darpi_cache1_list_create(&dst_ip) < 0) {
                exit(EXIT_FAILURE);
            }
            
            /*
             * Check in DARPI 3 Cache if this outbound request 
             * derives by an inbound request.
             */
            TAILQ_FOREACH(darpi_cache3_pos, &darpi_cache3_head, entries) {
                if (strcmp(inet_ntoa(darpi_cache3_pos->dc_ip), c_dst_ip) == 0) {
                    /*
                     * Entry found in DARPI 3 cache!
                     */
                    TAILQ_REMOVE(&darpi_cache3_head, darpi_cache3_pos, entries);
                    free(darpi_cache3_pos);
                    
                    return;
                }
            }
            
            /*
             * Entry not found in DARPI 3 cache!
             * DARPI 2 Cache Add/Refresh. 
             */
            if (darpi_cache2_list_create(&dst_ip) < 0) {
                exit(EXIT_FAILURE);
            }
        }
        /* 
         * Check if we are the destination address. 
         */
        else if (strcmp(c_dst_ip, inet_ntoa(dev.dev_inet4)) == 0) {
            /* 
             * Possible ARP Gratuitous for ARP Poisoning.
             * Search entry in DARPI 2 cache, if it matches it 
             * is to inserted in ARP cache, else if it doesn't 
             * exist, it is to deleted from ARP cache.
             */
            TAILQ_FOREACH(darpi_cache2_pos, &darpi_cache2_head, entries) {
                if (strcmp(inet_ntoa(darpi_cache2_pos->dc_ip), c_src_ip) == 0) {
                    /*
                     * Entry found in DARPI 2 cache!
                     */
                    TAILQ_REMOVE(&darpi_cache2_head, darpi_cache2_pos, entries);
                    free(darpi_cache2_pos);
                    
                    return;
                }
            }
			
            /*
             * Entry not found in DARPI 2 cache!
             */
			if (darpi_realtime_send_packet(&src_ip) < 0) {
				exit(EXIT_FAILURE);
            }
            
            /* 
             * DARPI 3 Cache Add/Refresh. 
             */
            if (darpi_cache3_list_create(&src_ip) < 0) {
                exit(EXIT_FAILURE);
            }
        }
    } else if (ntohs(arp_packet->ah_header.ar_op) == ARP_OP_REPLY) {
        /* 
         * Check if we are the destination address. 
         */
        if (strcmp(c_dst_mac, ether_ntoa(&(dev.dev_mac))) == 0 && 
            strcmp(c_dst_ip, inet_ntoa(dev.dev_inet4)) == 0) {
            /* 
             * Possible ARP Gratuitous for ARP Poisoning.
             * Search entry in DARPI 1 cache, if it matches it 
             * is to inserted in ARP cache, else if it doesn't 
             * exist, it is to deleted from ARP cache.
             */
            TAILQ_FOREACH(darpi_cache1_pos, &darpi_cache1_head, entries) {
                if (strcmp(inet_ntoa(darpi_cache1_pos->dc_ip), c_src_ip) == 0) {
                    /*
                     * Entry found in DARPI 1 cache!
                     */
                    TAILQ_REMOVE(&darpi_cache1_head, darpi_cache1_pos, entries);
                    free(darpi_cache1_pos);
						
                    memset(entry, '\0', 34);
                    snprintf(entry, 34, "%15s %17s", c_src_ip, c_src_mac);
                    entry[strlen(entry)] = '\0';
					
                    if (arp_cache_del(c_src_ip) < 0) {
                        exit(EXIT_FAILURE);
                    }
                    
                    if (arp_cache_add(entry) < 0) {
                        exit(EXIT_FAILURE);
                    }
					
                    aprintf(stdout, 1, "ARP cache, ACCEPT\n");
                    aprintf(stdout, 0, "\t src HW = <%s>\n", c_src_mac);
                    aprintf(stdout, 0, "\t src IP = <%s>\n", c_src_ip);
						
                    return;
                }
            }
			
            /*
             * Entry not found in DARPI 1 cache!
             */
			if (darpi_realtime_send_packet(&src_ip) < 0) {
				exit(EXIT_FAILURE);
            }
            
            if ((ret = arp_cache_del(c_src_ip)) < 0) {
                exit(EXIT_FAILURE);
            } else if (ret == 0) {
                aprintf(stdout, 1, "ARP cache, DENY\n");
                aprintf(stdout, 0, "\t src HW = <%s>\n", c_src_mac);
                aprintf(stdout, 0, "\t src IP = <%s>\n", c_src_ip);
            }
        }
    }
}

/*
 * DARPI Send ARP request Outbound
 * Read doc/DARPI.jpg algorithm.
 */
static int
darpi_realtime_send_packet(struct in_addr *dst_ip)
{
    struct ether_addr *dst_mac;
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *lnet;
        
    if ((lnet = libnet_init(LIBNET_LINK, dev.dev, errbuf)) == NULL) {
        ERROR(errbuf);
        return (-1);
    }
    
    dst_mac = ether_aton("ff:ff:ff:ff:ff:ff");
        
    if (libnet_autobuild_arp(ARPOP_REQUEST, 
                             (u_int8_t *) &(dev.dev_mac),	/* Source Mac */
                             (u_int8_t *) &(dev.dev_inet4),	/* Source IP */
                             (u_int8_t *) dst_mac,  /* Destination Mac */
                             (u_int8_t *) dst_ip,   /* Destination IP */
                             lnet ) < 0) {
        ERROR(libnet_geterror(lnet));
        libnet_destroy(lnet);
		return (-1);
    }
        
    if (libnet_autobuild_ethernet((u_int8_t *) dst_mac, 
        ETHERTYPE_ARP, lnet) < 0) {
        ERROR(libnet_geterror(lnet));
        libnet_destroy(lnet);
		return (-1);
    }
        
    /* Sends (Ethernet + Arp) Packet */
    if (libnet_write(lnet) < 0) {
        ERROR(libnet_geterror(lnet));
        libnet_destroy(lnet);
		return (-1);
    }
    
    libnet_destroy(lnet);
    return (0);
}    
    
/*
 * Create or adds DARPI cache 1 tail.
 */
static int 
darpi_cache1_list_create(struct in_addr *entry)
{
    struct in_addr ip;
		
    ip.s_addr = entry->s_addr;
		
    pthread_rwlock_wrlock(&wlock2);
		
    if (darpi_cache1_begin == NULL) { 
        TAILQ_INIT(&darpi_cache1_head);
			
        if ((darpi_cache1_begin = malloc(
            sizeof(struct darpi_cache1))) == NULL) {
            ERROR(strerror(errno));	
            pthread_rwlock_unlock(&wlock2);
				
            return (-1);
        }
			
        memcpy(&darpi_cache1_begin->dc_ip, &ip, sizeof(ip));
        darpi_cache1_begin->tm_entry = time(NULL);
        TAILQ_INSERT_HEAD(&darpi_cache1_head, darpi_cache1_begin, entries);
			
        pthread_rwlock_unlock(&wlock2);
			
        return (0);
    }
		
    if ((darpi_cache1_next = malloc(sizeof(struct darpi_cache1))) == NULL) {
        ERROR(strerror(errno));			
        pthread_rwlock_unlock(&wlock2);
			
        return (-1);
    }
		
    memcpy(&darpi_cache1_next->dc_ip, &ip, sizeof(ip));
    darpi_cache1_next->tm_entry = time(NULL);
    TAILQ_INSERT_TAIL(&darpi_cache1_head, darpi_cache1_next, entries);
		
    pthread_rwlock_unlock(&wlock2);
		
    return (0);	
}
	
/* 
 * DARPI cache 1 list signal handler.
 */
static void
darpi_cache1_list_check_thread_sigusr1(int sig)
{
		
    pthread_exit((void *) 0);
}
	
/*
 * DARPI Cache 1 entry timeout.
 * When DARPI reads ARP Request Outbound, it writes an 
 * entry in DARPI Cache, if this entry replies with ARP 
 * Reply Inbound it's ok, else if it doesn't replies, 
 * it probably doesn't exist. This timeout in this case, 
 * delete this entry from DARPI Cache. 
 */
static void *
darpi_cache1_list_check_thread(void *arg)
{
    struct sigaction saction;
    time_t tm_entry;
    int diff_time_entry = 0;
	
#ifdef NETBSD
    saction.sa_flags = 0;
#endif
    saction.sa_handler = darpi_cache1_list_check_thread_sigusr1;
	
    if (sigaction(SIGUSR1, &saction, NULL) < 0) {
        ERROR(strerror(errno));
		
        pthread_exit((void *) -1);
    }
    
    while (1) {
        /* 
         * Each 1 second, it check diff time of each entry.
         */
        if (sleep(1) > 0) {
            ERROR(strerror(errno));
            
            pthread_exit((void *) -1);
        }
        
        tm_entry = time(NULL);
        
        pthread_rwlock_rdlock(&rlock2);
        pthread_rwlock_wrlock(&wlock2);
        
        TAILQ_FOREACH(darpi_cache1_pos, &darpi_cache1_head, entries) {
            diff_time_entry = difftime(tm_entry, darpi_cache1_pos->tm_entry);
            
            if (diff_time_entry >= darpi_timeout) {
                TAILQ_REMOVE(&darpi_cache1_head, darpi_cache1_pos, entries);
                free(darpi_cache1_pos);
                
                diff_time_entry = 0;
                break;
            }
            
            diff_time_entry = 0;
        }
        
        pthread_rwlock_unlock(&wlock2);
        pthread_rwlock_unlock(&rlock2);        
    }
    
    pthread_exit((void *) 0);
}
	
/*
 * Destroy DARPI cache 1 tail.
 */
static void
darpi_cache1_list_destroy(void)
{
		
    pthread_rwlock_rdlock(&rlock2);
		
    while (TAILQ_EMPTY(&darpi_cache1_head) == 0) {
        pthread_rwlock_wrlock(&wlock2);
			
        darpi_cache1_pos = TAILQ_FIRST(&darpi_cache1_head);
			
        TAILQ_REMOVE(&darpi_cache1_head, darpi_cache1_pos, entries);
        free(darpi_cache1_pos);
			
        pthread_rwlock_unlock(&wlock2);
    }
		
    pthread_rwlock_unlock(&rlock2);
}
	
/*
 * Create or adds DARPI cache 2 tail.
 */
static int 
darpi_cache2_list_create(struct in_addr *entry)
{
    struct in_addr ip;
		
    ip.s_addr = entry->s_addr;
		
    pthread_rwlock_wrlock(&wlock3);
		
    if (darpi_cache2_begin == NULL) { 
        TAILQ_INIT(&darpi_cache2_head);
			
        if ((darpi_cache2_begin = malloc(
            sizeof(struct darpi_cache2))) == NULL) {
            ERROR(strerror(errno));	
            pthread_rwlock_unlock(&wlock3);
				
            return (-1);
        }
			
        memcpy(&darpi_cache2_begin->dc_ip, &ip, sizeof(ip));
        darpi_cache2_begin->tm_entry = time(NULL);
        TAILQ_INSERT_HEAD(&darpi_cache2_head, darpi_cache2_begin, entries);
			
        pthread_rwlock_unlock(&wlock3);
			
        return (0);
    }
		
    if ((darpi_cache2_next = malloc(sizeof(struct darpi_cache2))) == NULL) {
        ERROR(strerror(errno));			
        pthread_rwlock_unlock(&wlock3);
			
        return (-1);
    }
		
    memcpy(&darpi_cache2_next->dc_ip, &ip, sizeof(ip));
    darpi_cache2_next->tm_entry = time(NULL);
    TAILQ_INSERT_TAIL(&darpi_cache2_head, darpi_cache2_next, entries);
		
    pthread_rwlock_unlock(&wlock3);
		
    return (0);	
}
	
/* 
 * DARPI cache 2 list signal handler.
 */
static void
darpi_cache2_list_check_thread_sigusr1(int sig)
{
		
    pthread_exit((void *) 0);
}
	
/*
 * DARPI Cache 2 entry timeout.
 * When DARPI reads ARP Request Outbound, it writes an 
 * entry in DARPI Cache, if this entry replies with ARP 
 * Reply Inbound it's ok, else if it doesn't replies, 
 * it probably doesn't exist. This timeout in this case, 
 * delete this entry from DARPI Cache. 
 */
static void *
darpi_cache2_list_check_thread(void *arg)
{
    struct sigaction saction;
    time_t tm_entry;
    int diff_time_entry = 0;
        
#ifdef NETBSD
    saction.sa_flags = 0;
#endif
    saction.sa_handler = darpi_cache2_list_check_thread_sigusr1;
        
    if (sigaction(SIGUSR1, &saction, NULL) < 0) {
        ERROR(strerror(errno));
            
        pthread_exit((void *) -1);
    }
    
    while (1) {
        /* 
         * Each 1 second, it check diff time of each entry.
         */
        if (sleep(1) > 0) {
            ERROR(strerror(errno));
                
            pthread_exit((void *) -1);
        }
        
        tm_entry = time(NULL);
        
        pthread_rwlock_rdlock(&rlock3);
        pthread_rwlock_wrlock(&wlock3);
        
        TAILQ_FOREACH(darpi_cache2_pos, &darpi_cache2_head, entries) {
            diff_time_entry = difftime(tm_entry, darpi_cache2_pos->tm_entry);
            
            if (diff_time_entry >= darpi_timeout) {
                TAILQ_REMOVE(&darpi_cache2_head, darpi_cache2_pos, entries);
                free(darpi_cache2_pos);
                
                diff_time_entry = 0;
                break;
            }
            
            diff_time_entry = 0;
        }
            
        pthread_rwlock_unlock(&wlock3);
        pthread_rwlock_unlock(&rlock3);        
    }
        
    pthread_exit((void *) 0);
}
	
/*
 * Destroy DARPI 2 cache tail.
 */
static void
darpi_cache2_list_destroy(void)
{
		
    pthread_rwlock_rdlock(&rlock3);
		
    while (TAILQ_EMPTY(&darpi_cache2_head) == 0) {
        pthread_rwlock_wrlock(&wlock3);
			
        darpi_cache2_pos = TAILQ_FIRST(&darpi_cache2_head);
			
        TAILQ_REMOVE(&darpi_cache2_head, darpi_cache2_pos, entries);
        free(darpi_cache2_pos);
			
        pthread_rwlock_unlock(&wlock3);
    }
		
    pthread_rwlock_unlock(&rlock3);
}
    
/*
 * Create or adds DARPI cache 3 tail.
 */
static int     
darpi_cache3_list_create(struct in_addr *entry)
{
    struct in_addr ip;
		
    ip.s_addr = entry->s_addr;
		
    pthread_rwlock_wrlock(&wlock4);
		
    if (darpi_cache3_begin == NULL) { 
        TAILQ_INIT(&darpi_cache3_head);
			
        if ((darpi_cache3_begin = malloc(
            sizeof(struct darpi_cache3))) == NULL) {
            ERROR(strerror(errno));	
            pthread_rwlock_unlock(&wlock4);
				
            return (-1);
        }
			
        memcpy(&darpi_cache3_begin->dc_ip, &ip, sizeof(ip));
        darpi_cache3_begin->tm_entry = time(NULL);
        TAILQ_INSERT_HEAD(&darpi_cache3_head, darpi_cache3_begin, entries);
			
        pthread_rwlock_unlock(&wlock4);
        
        return (0);
    }
		
    if ((darpi_cache3_next = malloc(sizeof(struct darpi_cache3))) == NULL) {
        ERROR(strerror(errno));			
        pthread_rwlock_unlock(&wlock4);
			
        return (-1);
    }
		
    memcpy(&darpi_cache3_next->dc_ip, &ip, sizeof(ip));
    darpi_cache3_next->tm_entry = time(NULL);
    TAILQ_INSERT_TAIL(&darpi_cache3_head, darpi_cache3_next, entries);
		
    pthread_rwlock_unlock(&wlock4);
		
    return (0);	
}
	    
/* 
 * DARPI cache 3 list signal handler.
 */
static void
darpi_cache3_list_check_thread_sigusr1(int sig)
{
		
    pthread_exit((void *) 0);
}
	
/*
 * DARPI Cache 3 entry timeout.
 * When DARPI reads ARP Request Outbound, it writes an 
 * entry in DARPI Cache, if this entry replies with ARP 
 * Reply Inbound it's ok, else if it doesn't replies, 
 * it probably doesn't exist. This timeout in this case, 
 * delete this entry from DARPI Cache. 
 */
static void *
darpi_cache3_list_check_thread(void *arg)
{
    struct sigaction saction;
    time_t tm_entry;
    int diff_time_entry = 0;
        
#ifdef NETBSD
    saction.sa_flags = 0;
#endif
    saction.sa_handler = darpi_cache3_list_check_thread_sigusr1;
        
    if (sigaction(SIGUSR1, &saction, NULL) < 0) {
        ERROR(strerror(errno));
            
        pthread_exit((void *) -1);
    }
        
    while (1) {
        /* 
         * Each 1 second, it check diff time of each entry.
         */
        if (sleep(1) > 0) {
            ERROR(strerror(errno));
                
            pthread_exit((void *) -1);
        }
            
        tm_entry = time(NULL);
            
        pthread_rwlock_rdlock(&rlock4);
        pthread_rwlock_wrlock(&wlock4);
            
        TAILQ_FOREACH(darpi_cache3_pos, &darpi_cache3_head, entries) {
            diff_time_entry = difftime(tm_entry, darpi_cache3_pos->tm_entry);
                
            if (diff_time_entry >= darpi_timeout) {
                TAILQ_REMOVE(&darpi_cache3_head, darpi_cache3_pos, entries);
                free(darpi_cache3_pos);
                
                diff_time_entry = 0;
                break;
            }
                
            diff_time_entry = 0;
        }
            
        pthread_rwlock_unlock(&wlock4);
        pthread_rwlock_unlock(&rlock4);        
    }
        
    pthread_exit((void *) 0);
}
	
/*
 * Destroy DARPI 3 cache tail.
 */
static void
darpi_cache3_list_destroy(void)
{
		
    pthread_rwlock_rdlock(&rlock4);
		
    while (TAILQ_EMPTY(&darpi_cache3_head) == 0) {
        pthread_rwlock_wrlock(&wlock4);
			
        darpi_cache3_pos = TAILQ_FIRST(&darpi_cache3_head);
			
        TAILQ_REMOVE(&darpi_cache3_head, darpi_cache3_pos, entries);
        free(darpi_cache3_pos);
			
        pthread_rwlock_unlock(&wlock4);
    }
		
    pthread_rwlock_unlock(&rlock4);
}
    
/******************
 * HARPI handler: *
 ******************/
    
/*
 * HARPI manager signal handler.
 */
static void
harpi_manager_thread_sigusr1(int sig)
{

    sarpi_cache_list_destroy();
    darpi_cache1_list_destroy();
    darpi_cache2_list_destroy();
    darpi_cache3_list_destroy();
    pthread_exit((void *) 0);
}
	
/* 
 * Handles HARPI: 
 *
 * Working to parallel:
 *
 * 1) DARPI delete all found entries 
 * in the ARP cache to delete some poisoned 
 * hosts then it starts realtime execution
 * to reads the packets:
 *  - ARP Request
 *  - ARP Reply
 *
 * 2) SARPI through two thread for parallelism:
 *  - 1:    Update automatically the ARP cache
 *  - 2:    Works in soft real time, in other words it 
 *          listens to the inbound/outbound arp packets.
 */
static void *
harpi_manager_thread(void *arg)
{
    struct sigaction saction;
        
#ifdef NETBSD
    saction.sa_flags = 0;
#endif
    saction.sa_handler = harpi_manager_thread_sigusr1;
        
    if (sigaction(SIGUSR1, &saction, NULL) < 0) {
        ERROR(strerror(errno));
            
        pthread_exit((void *) -1);
    }
        
    /*
     * Iface work.
     */
    if (iface_manager() < 0) {
        pthread_exit((void *) -1);
    }
        
    if (iface_check_uplink() < 0) {
        pthread_exit((void *) -1);
    }
        
    iface_info_print();
        
    /* 
     * PID CPU Scheduling.
     */
    if (task_mode_cpu_priority(PRIO_PROCESS, getpid(), cpu_priority) < 0) {
        pthread_exit((void *) -1);
    }
        
    /* 
     * Delete all ARP Cache entries (Possible entries poisoned). 
     */
    if (arp_cache_del_all() < 0) {
        pthread_exit((void *) -1);
    }
        
    pthread_rwlock_init(&rlock, NULL);
    pthread_rwlock_init(&wlock, NULL);
    
    /* 
     * ARP Cache entries protected from file. 
     */
    if (sarpi_cache_file_restore() < 0) {
        exit(-1);
    }
	
    pthread_attr_init(&detach_attr);
    pthread_attr_setdetachstate(&detach_attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setschedpolicy(&detach_attr, SCHED_RR);
	
    /*
     * Thread 4 detached, update automatically the ARP cache. 
     */
    if (pthread_create(&thread[3], &detach_attr, 
                       sarpi_cache_list_refresh_thread, (void *) NULL) != 0) {
        ERROR(strerror(errno));
        sarpi_cache_list_destroy();
		
        pthread_exit((void *) -1);
    }
    
    /*
     * Thread 5 detached, inbound/outbound work.
     */
    if (harpi_realtime() < 0) {
        pthread_exit((void *) -1);
    }
        
    pthread_exit((void *) 0);
}
    
/*
 * HARPI Realtime execution, process all 
 * inbound/outbound ARP packets.
 */
static int
harpi_realtime(void)
{
        
    pthread_attr_init(&detach_attr);
    pthread_attr_setdetachstate(&detach_attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setschedpolicy(&detach_attr, SCHED_RR);
        
    /* 
     * Thread 5 detached, realtime inbound/outbound work.
     */
    if (pthread_create(&thread[4], &detach_attr, harpi_realtime_thread, 
                       (void *) NULL) != 0) {
        ERROR(strerror(errno));
            
        return (-1);
    }
    
    pthread_attr_destroy(&detach_attr);
    
    pthread_attr_init(&detach_attr);
    pthread_attr_setdetachstate(&detach_attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setschedpolicy(&detach_attr, SCHED_RR);
    
    /* 
     * Thread 6 detached, Check each DARPI Cache 1 entry with 
     * timeout, possible host doesn't present in the network.
     */
    pthread_create(&thread[5], &detach_attr, 
                   darpi_cache1_list_check_thread, (void *) NULL);
    
    /* 
     * Thread 7 detached, Check each DARPI Cache 2 entry with 
     * timeout, possible host doesn't present in the network.
     */
    pthread_create(&thread[6], &detach_attr, 
                   darpi_cache2_list_check_thread, (void *) NULL);
    
    /* 
     * Thread 8 detached, Check each DARPI Cache 3 entry with 
     * timeout, possible host doesn't present in the network.
     */
    pthread_create(&thread[7], &detach_attr, 
                   darpi_cache3_list_check_thread, (void *) NULL);
    
    pthread_attr_destroy(&detach_attr);
    
    darpi_cache1_list_destroy();
    darpi_cache2_list_destroy();
    darpi_cache3_list_destroy();
    
    return (0);
}
    
/*
 * HARPI realtime signal handler.
 */
static void
harpi_realtime_thread_sigusr1(int sig)
{
		
    pthread_exit((void *) 0);
}
	
/*
 * Use thread for non blocking to pcap_loop().
 */
static void *
harpi_realtime_thread(void *arg)
{
    struct sigaction saction;
    pcap_t *pcap;
        
#ifdef NETBSD
    saction.sa_flags = 0;
#endif
    saction.sa_handler = harpi_realtime_thread_sigusr1;
        
    if (sigaction(SIGUSR1, &saction, NULL) < 0) {
        ERROR(strerror(errno));
            
        pthread_exit((void *) -1);
    }
        
    if ((pcap = harpi_realtime_open_packets()) == NULL) {
        pthread_exit((void *) -1);
    }
        
    pthread_rwlock_init(&rlock2, NULL);
    pthread_rwlock_init(&wlock2, NULL);
    pthread_rwlock_init(&rlock3, NULL);
    pthread_rwlock_init(&wlock3, NULL);
    pthread_rwlock_init(&rlock4, NULL);
    pthread_rwlock_init(&wlock4, NULL);
    
    while (1) {
        if (pcap_loop(pcap, 1, harpi_realtime_read_packets, NULL) < 0) {
            ERROR(pcap_geterr(pcap));
                
            pthread_rwlock_destroy(&wlock2);
            pthread_rwlock_destroy(&rlock2);
            pthread_rwlock_destroy(&wlock3);
            pthread_rwlock_destroy(&rlock3);
            pthread_rwlock_destroy(&wlock4);
            pthread_rwlock_destroy(&rlock4);
            harpi_realtime_close_packets(pcap);
                
            pthread_exit((void *) -1);
        }
    }
        
    pthread_rwlock_destroy(&wlock2);
    pthread_rwlock_destroy(&rlock2);
    pthread_rwlock_destroy(&wlock3);
    pthread_rwlock_destroy(&rlock3);
    pthread_rwlock_destroy(&wlock4);
    pthread_rwlock_destroy(&rlock4);
    harpi_realtime_close_packets(pcap);
        
    pthread_exit((void *) 0);
}
    
/*
 * Open pcap file descriptor.
 */
static pcap_t *
harpi_realtime_open_packets(void)
{
    struct bpf_program compiled_filter;
    char errbuf[PCAP_ERRBUF_SIZE], *filter = "arp";
    pcap_t *pcap;
#ifndef LINUX
    unsigned int op = 1;
#endif
        
    if ((pcap = pcap_open_live(dev.dev, BUFSIZ, 0, 0, errbuf)) == NULL) {
        ERROR(errbuf);
            
        return (NULL);
    }
        
#ifndef LINUX
    /* 
     * BSD, differently from linux does not 
     * support automatic socket soft real time 
     * (Linux Socket Filter). 
     * Therefore on BSD platform it's necessary 
     * to use this I/O Control.
     */
    if (ioctl(pcap_fileno(pcap), BIOCIMMEDIATE, &op) < 0) {
        ERROR(strerror(errno));
            
        return (NULL);
    }
#endif
        
    if (pcap_compile(pcap, &compiled_filter, filter, 0, 
                     dev.dev_netmask.s_addr) < 0) {
        ERROR(pcap_geterr(pcap));
        harpi_realtime_close_packets(pcap);
            
        return (NULL);
    }
        
    if (pcap_setfilter(pcap, &compiled_filter) < 0) {
        ERROR(pcap_geterr(pcap));
        harpi_realtime_close_packets(pcap);
            
        return (NULL);
    }	
        
    pcap_freecode(&compiled_filter);
    return (pcap);
}

/*
 * Close pcap file descriptor.
 */
static void
harpi_realtime_close_packets(pcap_t *pcap)
{
        
    pcap_close(pcap);
}
    
/* 
 * HARPI I/O.
 * Read doc/HARPI.jpg algorithm.
 */
static void
harpi_realtime_read_packets(unsigned char *arg, const struct pcap_pkthdr 
                            *header, const unsigned char *packet)
{
    struct ether_addr src_mac, dst_mac;
    struct in_addr src_ip, dst_ip;
    struct arp_header *arp_packet;
    char c_src_ip[16], c_src_mac[18], c_dst_ip[16], c_dst_mac[18], c_ap_ip[16],
         entry[34];
    int i, ret = 0, state = 0;
        
    /* 
     * ARP Packet.
     */
    arp_packet = (struct arp_header *) (packet + dev.dev_offset);
        
    /*
     * Convert source MAC/IPv4 string.
     */
    snprintf(c_src_ip, 16, "%d.%d.%d.%d", 
             arp_packet->ah_addresses.ar_spa[0], 
             arp_packet->ah_addresses.ar_spa[1],
             arp_packet->ah_addresses.ar_spa[2], 
             arp_packet->ah_addresses.ar_spa[3]);
    inet_aton(c_src_ip, &src_ip);
    
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        src_mac.octet[i] = arp_packet->ah_addresses.ar_sha[i];
    }
    strncpy(c_src_mac, ether_ntoa(&src_mac), sizeof(char) * 18);
    c_src_mac[sizeof(char) * strlen(c_src_mac)] = '\0';
        
    /*
     * Convert destination MAC/IPv4 string.
     */
    snprintf(c_dst_ip, 16, "%d.%d.%d.%d", 
             arp_packet->ah_addresses.ar_tpa[0], 
             arp_packet->ah_addresses.ar_tpa[1],
             arp_packet->ah_addresses.ar_tpa[2], 
             arp_packet->ah_addresses.ar_tpa[3]);
    inet_aton(c_dst_ip, &dst_ip);
        
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        dst_mac.octet[i] = arp_packet->ah_addresses.ar_tha[i];
    }
    strncpy(c_dst_mac, ether_ntoa(&dst_mac), sizeof(char) * 18);
    c_dst_mac[sizeof(char) * strlen(c_dst_mac)] = '\0';
    
    if (ntohs(arp_packet->ah_header.ar_op) == ARP_OP_REQUEST) {
        /* 
         * Check if it is a broadcast address. 
         */
        if (strcmp(c_src_ip, inet_ntoa(dev.dev_inet4)) != 0 &&
            strcmp(c_dst_ip, inet_ntoa(dev.dev_inet4)) != 0 &&
            strcmp(c_src_ip, c_dst_ip) == 0) {
            /* 
             * Search ARP reply/request source in SARPI (ARP cache) entries. 
             */
            TAILQ_FOREACH(sarpi_cache_pos, &sarpi_cache_head, entries) {
                /*
                 * Convert MAC/IPv4 to string form.
                 */
                memset(c_ap_ip, '\0', sizeof(char) * 16);
                strncpy(c_ap_ip, inet_ntoa(sarpi_cache_pos->sc_ip), 
                        sizeof(char) * 16);
                c_ap_ip[sizeof(char) * strlen(c_ap_ip)] = '\0';
                
                state = 1;
                
                /* 
                 * In request, possible source address poisoned.
                 * In reply, possible ARP Gratuitous for ARP poisoning.
                 * Check if source is found in SARPI Cache. 
                 */
                if (strcmp(c_src_ip, c_ap_ip) == 0) {
                    /* 
                     * Source is Found! We reset static entry.
                     */
                    state = 0;
                    
                    aprintf(stdout, 1, "ARP cache, REFRESH\n");
                    
                    /* 
                     * Refresh static ARP Cache entry. 
                     */
                    snprintf(entry, 34, "%15s %17s", 
                             inet_ntoa(sarpi_cache_pos->sc_ip),
                             ether_ntoa(&(sarpi_cache_pos->sc_mac)));
                    entry[strlen(entry)] = '\0';
                    
                    if (arp_cache_del(c_src_ip) < 0) {
                        exit(EXIT_FAILURE);
                    }
                    
                    if (arp_cache_add(entry) < 0) {
                        exit(EXIT_FAILURE);
                    } 
                    
                    aprintf(stdout, 0, "\t src HW = <%s>\n", 
                            ether_ntoa(&(sarpi_cache_pos->sc_mac)));
                    aprintf(stdout, 0, "\t src IP = <%s>\n", 
                            inet_ntoa(sarpi_cache_pos->sc_ip));
                    
                    break;
                }
            }
            
            /*
             * Source is not found in SARPI Cache.
             */
            if (state == 1) {
                if (darpi_realtime_send_packet(&src_ip) < 0) {
                    exit(EXIT_FAILURE);
                }
            
                if ((ret = arp_cache_del(c_src_ip)) < 0) {
                    exit(EXIT_FAILURE);
                } else if (ret == 0) {
                    aprintf(stdout, 1, "ARP cache, DENY\n");
                    aprintf(stdout, 0, "\t src HW = <%s>\n", c_src_mac);
                    aprintf(stdout, 0, "\t src IP = <%s>\n", c_src_ip);
                }
            }
        }
        /* 
         * Check if we are the source address. 
         */
        else if (strcmp(c_src_mac, ether_ntoa(&(dev.dev_mac))) == 0 && 
                 strcmp(c_src_ip, inet_ntoa(dev.dev_inet4)) == 0) {
            /* 
             * Search ARP Reply/Request source in SARPI (ARP cache) entries. 
             */
            TAILQ_FOREACH(sarpi_cache_pos, &sarpi_cache_head, entries) {
                /*
                 * Convert MAC/IPv4 to string form.
                 */
                memset(c_ap_ip, '\0', sizeof(char) * 16);
                strncpy(c_ap_ip, inet_ntoa(sarpi_cache_pos->sc_ip), 
                        sizeof(char) * 16);
                c_ap_ip[sizeof(char) * strlen(c_ap_ip)] = '\0';
                    
                state = 1;
                
                /*
                 * Check if destination is not found in SARPI Cache. 
                 */
                if (strcmp(c_dst_ip, c_ap_ip) == 0) {
                    /*
                     * Destination found in SARPI Cache!
                     */
                    state = 0;
                    break;
                }
            }
            
            /* 
             * Destination is not found in SARPI Cache!
             */
            if (state == 1) {
                /* 
                 * DARPI 1 Cache Add/Refresh. 
                 */
                if (darpi_cache1_list_create(&dst_ip) < 0) {
                    exit(EXIT_FAILURE);
                }
                
                /*
                 * Check in DARPI 3 Cache if this outbound request 
                 * derives by an inbound request.
                 */
                TAILQ_FOREACH(darpi_cache3_pos, &darpi_cache3_head, entries) {
                    if (strcmp(inet_ntoa(darpi_cache3_pos->dc_ip), 
                               c_dst_ip) == 0) {
                        /*
                         * Entry found in DARPI 3 cache!
                         */
                        TAILQ_REMOVE(&darpi_cache3_head, darpi_cache3_pos, 
                                     entries);
                        free(darpi_cache3_pos);
                        
                        return;
                    }
                }
                
                /*
                 * Entry not found in DARPI 3 cache!
                 * DARPI 2 Cache Add/Refresh. 
                 */
                if (darpi_cache2_list_create(&dst_ip) < 0) {
                    exit(EXIT_FAILURE);
                }
            }
        }
        /* 
         * Check if we are the destination address. 
         */
        else if (strcmp(c_dst_ip, inet_ntoa(dev.dev_inet4)) == 0) {
            /* 
             * Search ARP reply/request source in SARPI (ARP cache) entries. 
             */
            TAILQ_FOREACH(sarpi_cache_pos, &sarpi_cache_head, entries) {
                /*
                 * Convert MAC/IPv4 to string form.
                 */
                memset(c_ap_ip, '\0', sizeof(char) * 16);
                strncpy(c_ap_ip, inet_ntoa(sarpi_cache_pos->sc_ip), 
                        sizeof(char) * 16);
                c_ap_ip[sizeof(char) * strlen(c_ap_ip)] = '\0';
                    
                state = 1;
                
                /* 
                 * In request, possible source address poisoned.
                 * In reply, possible ARP Gratuitous for ARP poisoning.
                 * Check if source is found in SARPI Cache. 
                 */
                if (strcmp(c_src_ip, c_ap_ip) == 0) {
                    /* 
                     * Source is Found! We will reset static entry with reply.
                     */
                    state = 0;
                    break;
                }
            }
            
            /* 
             * Destination is not found in SARPI Cache!
             */
            if (state == 1) {
                /* 
                 * Possible ARP Gratuitous for ARP Poisoning.
                 * Search entry in DARPI 2 cache, if it matches it 
                 * is to inserted in ARP cache, else if it doesn't 
                 * exist, it is to deleted from ARP cache.
                 */
                TAILQ_FOREACH(darpi_cache2_pos, 
                              &darpi_cache2_head, entries) {
                    if (strcmp(inet_ntoa(darpi_cache2_pos->dc_ip), 
                               c_src_ip) == 0) {
                        /*
                         * Entry found in DARPI 2 cache!
                         */
                        TAILQ_REMOVE(&darpi_cache2_head, 
                                     darpi_cache2_pos, entries);
                        free(darpi_cache2_pos);
                        
                        return;
                    }
                }
                
                /*
                 * Entry not found in DARPI 2 cache!
                 */
                if (darpi_realtime_send_packet(&src_ip) < 0) {
                    exit(EXIT_FAILURE);
                }
                
                /* 
                 * DARPI 3 Cache Add/Refresh. 
                 */
                if (darpi_cache3_list_create(&src_ip) < 0) {
                    exit(EXIT_FAILURE);
                }
            }
        }
    } else if (ntohs(arp_packet->ah_header.ar_op) == ARP_OP_REPLY) {
        /* 
         * Check if we are the destination address. 
         */
        if (strcmp(c_dst_mac, ether_ntoa(&(dev.dev_mac))) == 0 && 
            strcmp(c_dst_ip, inet_ntoa(dev.dev_inet4)) == 0) {
            /* 
             * Search ARP reply/request source in SARPI (ARP cache) entries. 
             */
            TAILQ_FOREACH(sarpi_cache_pos, &sarpi_cache_head, entries) {
                /*
                 * Convert MAC/IPv4 to string form.
                 */
                memset(c_ap_ip, '\0', sizeof(char) * 16);
                strncpy(c_ap_ip, inet_ntoa(sarpi_cache_pos->sc_ip), 
                        sizeof(char) * 16);
                c_ap_ip[sizeof(char) * strlen(c_ap_ip)] = '\0';
                
                state = 1;
                
                /* 
                 * In request, possible source address poisoned.
                 * In reply, possible ARP Gratuitous for ARP poisoning.
                 * Check if source is found in SARPI Cache. 
                 */
                if (strcmp(c_src_ip, c_ap_ip) == 0) {
                    /* 
                     * Source is Found! We reset static entry.
                     */
                    state = 0;
                    
                    aprintf(stdout, 1, "ARP cache, REFRESH\n");
                    
                    /* 
                     * Refresh static ARP Cache entry. 
                     */
                    snprintf(entry, 34, "%15s %17s", 
                             inet_ntoa(sarpi_cache_pos->sc_ip),
                             ether_ntoa(&(sarpi_cache_pos->sc_mac)));
                    entry[strlen(entry)] = '\0';
                    
                    if (arp_cache_del(c_src_ip) < 0) {
                        exit(EXIT_FAILURE);
                    }
                    
                    if (arp_cache_add(entry) < 0) {
                        exit(EXIT_FAILURE);
                    } 
                    
                    aprintf(stdout, 0, "\t src HW = <%s>\n", 
                            ether_ntoa(&(sarpi_cache_pos->sc_mac)));
                    aprintf(stdout, 0, "\t src IP = <%s>\n", 
                            inet_ntoa(sarpi_cache_pos->sc_ip));
                    
                    break;
                }
            }
                
            /*
             * Source is not found in SARPI Cache.
             */
            if (state == 1) {
                /* 
                 * Possible ARP Gratuitous for ARP Poisoning.
                 * Search entry in DARPI 1 cache, if it matches it 
                 * is to inserted in ARP cache, else if it doesn't 
                 * exist, it is to deleted from ARP cache.
                 */
                TAILQ_FOREACH(darpi_cache1_pos, &darpi_cache1_head, entries) {
                    if (strcmp(inet_ntoa(darpi_cache1_pos->dc_ip), 
                               c_src_ip) == 0) {
                        /*
                         * Entry found in DARPI 1 cache!
                         */
                        TAILQ_REMOVE(&darpi_cache1_head, 
                                     darpi_cache1_pos, entries);
                        free(darpi_cache1_pos);
						
                        memset(entry, '\0', 34);
                        snprintf(entry, 34, "%15s %17s", c_src_ip, c_src_mac);
                        entry[strlen(entry)] = '\0';
                        
                        if (arp_cache_del(c_src_ip) < 0) {
                            exit(EXIT_FAILURE);
                        }
                        
                        if (arp_cache_add(entry) < 0) {
                            exit(EXIT_FAILURE);
                        }
                        
                        aprintf(stdout, 1, "ARP cache, ACCEPT\n");
                        aprintf(stdout, 0, "\t src HW = <%s>\n", c_src_mac);
                        aprintf(stdout, 0, "\t src IP = <%s>\n", c_src_ip);
						
                        return;
                    }
                }
                
                /*
                 * Entry not found in DARPI 1 cache!
                 */
                if (darpi_realtime_send_packet(&src_ip) < 0) {
                    exit(EXIT_FAILURE);
                }
                
                if ((ret = arp_cache_del(c_src_ip)) < 0) {
                    exit(EXIT_FAILURE);
                } else if (ret == 0) {
                    aprintf(stdout, 1, "ARP cache, DENY\n");
                    aprintf(stdout, 0, "\t src HW = <%s>\n", c_src_mac);
                    aprintf(stdout, 0, "\t src IP = <%s>\n", c_src_ip);
                }
            }
        }
        /* 
         * Check if we are the source address. 
         */
        else if (strcmp(c_src_mac, ether_ntoa(&(dev.dev_mac))) == 0 && 
            strcmp(c_src_ip, inet_ntoa(dev.dev_inet4)) == 0) {
            /* 
             * Search ARP reply/request source in SARPI (ARP cache) entries. 
             */
            TAILQ_FOREACH(sarpi_cache_pos, &sarpi_cache_head, entries) {
                /*
                 * Convert MAC/IPv4 to string form.
                 */
                memset(c_ap_ip, '\0', sizeof(char) * 16);
                strncpy(c_ap_ip, inet_ntoa(sarpi_cache_pos->sc_ip), 
                        sizeof(char) * 16);
                c_ap_ip[sizeof(char) * strlen(c_ap_ip)] = '\0';
                
                state = 1;
                
                /* 
                 * In request, possible source address poisoned.
                 * In reply, possible ARP Gratuitous for ARP poisoning.
                 * Check if source is found in SARPI Cache. 
                 */
                if (strcmp(c_dst_ip, c_ap_ip) == 0) {
                    /* 
                     * Source is Found! We reset static entry.
                     */
                    state = 0;
                    
                    aprintf(stdout, 1, "ARP cache, REFRESH\n");
                    
                    /* 
                     * Refresh static ARP Cache entry. 
                     */
                    snprintf(entry, 34, "%15s %17s", 
                             inet_ntoa(sarpi_cache_pos->sc_ip),
                             ether_ntoa(&(sarpi_cache_pos->sc_mac)));
                    entry[strlen(entry)] = '\0';
                    
                    if (arp_cache_del(c_dst_ip) < 0) {
                        exit(EXIT_FAILURE);
                    } 
                    
                    if (arp_cache_add(entry) < 0) {
                        exit(EXIT_FAILURE);
                    } 
                    
                    aprintf(stdout, 0, "\t src HW = <%s>\n", 
                            ether_ntoa(&(sarpi_cache_pos->sc_mac)));
                    aprintf(stdout, 0, "\t src IP = <%s>\n", 
                            inet_ntoa(sarpi_cache_pos->sc_ip));
                    
                    break;
                }
            }
        }
    }
}
        
/*****************
 * Misc handler: *
 *****************/

/* 
 * My printf() with logging mode.
 */
static void 
aprintf(FILE *stream, int ltime, char *fmt, ...)
{
    struct tm tm_cur;
    time_t time_cur;
    FILE *log_fstream;
    va_list ap;

    if (stream != NULL) {
        if (ltime == 1) {
            time_cur = time(NULL);
            tm_cur = *(struct tm *) localtime(&time_cur);
            fprintf(stream, "%02d:%02d:%02d ", 	
                    tm_cur.tm_hour, tm_cur.tm_min, tm_cur.tm_sec);	
        }

        va_start(ap, fmt);
        vfprintf(stream, fmt, ap);
        va_end(ap);
    }

    if (log_mode == 0) {
        if ((log_fstream = task_mode_log_open()) == NULL) {
            kill(pid_main, SIGTERM);
			
            exit(EXIT_FAILURE);
        }

        if (ltime == 1) {
            time_cur = time(NULL);
            tm_cur = *(struct tm *) localtime(&time_cur);
            fprintf(log_fstream, "%02d:%02d:%02d ", 	
                    tm_cur.tm_hour, tm_cur.tm_min, tm_cur.tm_sec);	
        }

        va_start(ap, fmt);
        vfprintf(log_fstream, fmt, ap);
        va_end(ap);
		
        fflush(log_fstream);

        task_mode_log_close(log_fstream);
    }
}

/*
 * Prints my license.
 */
static void
license(void)
{

#define COPYRIGHT                                                         \
"Copyright (C) 2008-2014 Andrea Di Pasquale <spikey.it@gmail.com>\n"      \
"All rights reserved.\n"                                                  \
"\n"                                                                      \
"Redistribution and use in source and binary forms, with or without\n"    \
"modification, are permitted provided that the following conditions\n"    \
"are met:\n"                                                              \
"1. Redistributions of source code must retain the above copyright\n"     \
"   notice(s), this list of conditions and the following disclaimer as\n" \
"   the first lines of this file unmodified other than the possible\n"    \
"   addition of one or more copyright notices.\n"                         \
"2. Redistributions in binary form must reproduce the above copyright\n"  \
"   notice(s), this list of conditions and the following disclaimer in "  \
"the\n"                                                                   \
"   documentation and/or other materials provided with the "              \
"distribution.\n"                                                         \
"\n"                                                                      \
"THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER(S) ``AS IS'' AND ANY\n"\
"EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE "      \
"IMPLIED\n"                                                               \
"WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR "             \
"PURPOSE ARE\n"                                                           \
"DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) BE "               \
"LIABLE FOR ANY\n"                                                        \
"DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL "     \
"DAMAGES\n"                                                               \
"(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR\n"    \
"SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) "     \
"HOWEVER\n"                                                               \
"CAUSED AND ON ANY THEORY OF LIABILITY, WHETER IN CONTRACT, STRICT\n"     \
"LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY "  \
"WAY\n"                                                                   \
"OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF " \
"SUCH\n"                                                                  \
"DAMAGE.\n\n"

    printf(COPYRIGHT);

#undef COPYRIGHT
}

/*
 * Prints version.
 */
static void
version(void)
{
	
    printf("ArpON \"ARP handler inspection\" 2.7.2 " \
           "(http://arpon.sourceforge.net)\n\n");
}

/*
 * Prints help summary page.
 */
static void
help(void)
{

#define HELP                                                                \
"Usage: arpon [Options] {SARPI | DARPI | HARPI}\n"                          \
"\n"                                                                        \
"TASK MODE\n"                                                               \
"  -n, --nice             <Nice>         Sets PID's CPU priority\n"         \
"                                        (Default Nice: %d)\n"              \
"  -p, --pid-file         <Pid file>     Sets the pid file\n"               \
"                                        (Default: %s)\n"                   \
"  -q, --quiet                           Works in background task\n"        \
"\n"                                                                        \
"LOG MODE\n"                                                                \
"  -f, --log-file         <Log file>     Sets the log file\n"               \
"                                        (Default: %s)\n"                   \
"  -g, --log                             Works in logging mode\n"           \
"\n"                                                                        \
"DEVICE MANAGER\n"                                                          \
"  -i, --iface            <Iface>        Sets your device manually\n"       \
"  -o, --iface-auto                      Sets device automatically\n"       \
"  -l, --iface-list                      Prints all supported interfaces\n" \
"\n"                                                                        \
"STATIC ARP INSPECTION\n"                                                   \
"  -c, --sarpi-cache      <Cache file>   Sets SARPI entries from file\n"    \
"                                        (Default: %s)\n"                   \
"  -x, --sarpi-timeout    <Timeout>      Sets SARPI Cache refresh timeout\n"\
"                                        (Default: %d minuts)\n"            \
"  -S, --sarpi                           Manages ARP Cache statically\n"    \
"\n"                                                                        \
"DYNAMIC ARP INSPECTION\n"                                                  \
"  -y, --darpi-timeout    <Timeout>      Sets DARPI entries response max "  \
"timeout\n"                                                                 \
"                                        (Default: %d seconds)\n"           \
"  -D, --darpi                           Manages ARP Cache dynamically\n"   \
"\n"                                                                        \
"HYBRID ARP INSPECTION\n"                                                   \
"  -c, --sarpi-cache      <Cache file>   Sets HARPI entries from file\n"    \
"                                        (Default: %s)\n"                   \
"  -x, --sarpi-timeout    <Timeout>      Sets HARPI Cache refresh timeout\n"\
"                                        (Default: %d minuts)\n"            \
"  -y, --darpi-timeout    <Timeout>      Sets HARPI entries response max "  \
"timeout\n"                                                                 \
"                                        (Default: %d seconds)\n"           \
"  -H, --harpi                           Manages ARP Cache\n"               \
"                                        statically and dynamically\n"      \
"\n"                                                                        \
"MISC FEATURES\n"                                                           \
"  -e, --license                         Prints license page\n"             \
"  -v, --version                         Prints version number\n"           \
"  -h, --help                            Prints help summary page\n"        \
"\n"                                                                        \
"SEE THE MAN PAGE FOR MANY DESCRIPTIONS AND EXAMPLES\n\n"

    printf(HELP, cpu_priority, pid_file, log_file, 
           sarpi_cache_file, sarpi_timeout, darpi_timeout,
           sarpi_cache_file, sarpi_timeout, darpi_timeout);
	
#undef HELP
}

/*****************
 * Main handler: *
 *****************/

/*
 * Main signal handler.
 */
static int
main_signal(void)
{
		
    pthread_attr_init(&join_attr);
    pthread_attr_setschedpolicy(&join_attr, SCHED_RR);
		
    /*
     * Thread 1 joinabled, signal handler. 
     */
    if (pthread_create(&thread[0], &join_attr, 
        main_signal_thread, (void *) NULL) != 0) {
        ERROR(strerror(errno));
        pthread_attr_destroy(&join_attr);
		
        return (-1);
    }
		
    pthread_join(thread[0], NULL);
    pthread_attr_destroy(&join_attr);
	
    return (0);
}
	
/*
 * This thread is main signal handler of:
 *  - SIGINT, SIGTERM, SIGQUIT: Exit
 *  - SIGHUP, SIGCONT: Reboot
 * and handler for all threads.
 */
static void *
main_signal_thread(void *arg)
{
    int sig;
	
    while (1) {
#ifndef SOLARIS
        sigwait(&sigse, &sig);
#else
        sig = sigwait(&sigse);
#endif
        switch (sig) {
        case (SIGINT):
        case (SIGTERM):
        case (SIGQUIT):
            switch (dinspec) {
            case (INSPEC_SARPI):
                aprintf(stdout, 0, "\r\nSARPI Interrupt...\n\n");
                break;
			
            case (INSPEC_DARPI):
                aprintf(stdout, 0, "\r\nDARPI Interrupt...\n\n");
                break;
                    
            case (INSPEC_HARPI):
                aprintf(stdout, 0, "\r\nHARPI Interrupt...\n\n");
                break;
			
            case (INSPEC_NULL):
                break;
            }
			
            exit(-1);
				
        case (SIGHUP):
        case (SIGCONT):
            /*
             * Stop all threads and start their (Reboot).
             * Thread[0] = Signal is not restarted
             * Thread[1] = SARPI/DARPI/HARPI manager yes
             * Thread[2] = Iface uplink yes
             * Thread[3] = SARPI/DARPI/HARPI 1° Thread yes
             * Thread[4] = SARPI/DARPI/HARPI 2° Thread yes
             * Thread[5] = DARPI/HARPI 3° Thread yes
             * Thread[6] = HARPI 4° Thread yes
			 */
            main_stop();
			
            if (main_start() < 0) {
                pthread_exit((void *) -1);
            }
            break;
				
        default:
            break;
        }
    }
	
    pthread_exit((void *) 0);
}
	
/*
 * Start all threads in this order:
 *  - SARPI:
 *      SARPI manager -> Iface uplink -> SARPI 1° & 2° 
 *
 *  - DARPI:
 *      DARPI manager -> Iface uplink -> DARPI 1° & 2° & 3° & 4°
 *
 *	- HARPI:
 *		HARPI manager -> Iface uplink -> HARPI 1° & 2° & 3° & 4° & 5°
 */
static int
main_start(void)
{
    pthread_attr_init(&detach_attr);
    pthread_attr_setdetachstate(&detach_attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setschedpolicy(&detach_attr, SCHED_RR);
		
    switch (dinspec) {
    case (INSPEC_SARPI):
        /*
         * Thread 2 detached, start SARPI manager.
         */
        if (pthread_create(&thread[1], &detach_attr, sarpi_manager_thread, 
            (void *) NULL) != 0) {
            ERROR(strerror(errno));
					
            return (-1);
        }
			
        pthread_attr_destroy(&detach_attr);
        break;
				
    case (INSPEC_DARPI):
        /*
         * Thread 2 detached, start DARPI manager.
         */
        if (pthread_create(&thread[1], &detach_attr, darpi_manager_thread, 
            (void *) NULL) != 0) {
            ERROR(strerror(errno));
				
            return (-1);
        }
				
        pthread_attr_destroy(&detach_attr);
        break;
            
    case (INSPEC_HARPI):
        /*
         * Thread 2 detached, start HARPI manager.
         */
        if (pthread_create(&thread[1], &detach_attr, harpi_manager_thread, 
                           (void *) NULL) != 0) {
            ERROR(strerror(errno));
				
            return (-1);
        }
            
        pthread_attr_destroy(&detach_attr);
        break;
				
    case (INSPEC_NULL):
        break;
    }
		
    return (0);
}
	
/*
 * Stop these threads:
 * thread[0] = Signal handler is not stopped
 * thread[1] = SARPI/DARPI/HARPI manager yes
 * thread[2] = Iface uplink yes
 * thread[3] = SARPI/DARPI/HARPI 1° thread yes
 * thread[4] = SARPI/DARPI/HARPI 2° thread yes
 * thread[5] = DARPI/HARPI 3° thread yes
 * thread[6] = DARPU/HARPI 4° thread yes
 * thread[7] = HARPI 5° thread yes.
 */
static void 
main_stop(void)
{
    int i;
		
    for (i = 1; i < 8; i++) {
        pthread_kill(thread[i], SIGUSR1);
    }
}
	
/*
 * Main. 
 */
int
main(int argc, char *argv[], char *envp[])
{
    struct option longopts[] = {
        { "nice",           required_argument,  NULL,   'n' },
        { "pid-file",       required_argument,  NULL,   'p' },
        { "quiet",          no_argument,        NULL,   'q' },	
        { "log-file",       required_argument,  NULL,   'f' },
        { "log",            no_argument,        NULL,   'g' },
        { "iface",          required_argument,  NULL,   'i' },
        { "iface-auto",     no_argument,        NULL,   'o' },
        { "iface-list",     no_argument,        NULL,   'l' },
        { "sarpi-cache",    required_argument,  NULL,   'c' },
        { "sarpi-timeout",  required_argument,  NULL,   'x' },
        { "sarpi",          no_argument,        NULL,   'S' },
        { "darpi-timeout",  required_argument,  NULL,   'y' },	
        { "darpi",          no_argument,        NULL,   'D' },
        { "harpi",          no_argument,        NULL,   'H' },
        { "license",        no_argument,        NULL,   'e' },
        { "version",        no_argument,        NULL,   'v' },
        { "help",           no_argument,        NULL,   'h' },
        { NULL,             0,                  NULL,    0  }	    
    };
    int gopt, j;

    /*
     * Check if SARPI or DARPI timeout is setted without option.
     */
    j = 0;

    /* 
     * Sanitize environment from LD_PRELOAD attacks. 
     */
    if (getenv("LD_PRELOAD") != NULL) {
        unsetenv("LD_PRELOAD");
        execve(argv[0], argv, envp);
    }
	
    aprintf(stdout, 0, "\n");
	
    if (getuid() != 0x0) {
        aprintf(stderr, 0, "ERROR: must run as root!\n\n");
        return (-1);
    }
	
    if (argc == 1) {
        aprintf(stderr, 0, 
                "ERROR: Use -h or --help for more information.\n\n");
		
        return (0);
    }
			  
    pid_main = getpid();
	
    while ((gopt = getopt_long(argc, argv, "n:p:qf:gi:olc:x:Sy:DHevh", 
            longopts, NULL)) != -1) { 
        switch(gopt) {
        case ('n'):
            cpu_priority = atoi(optarg);
            break;

        case ('p'):
            pid_file = optarg;
            break;
				
        case ('q'):
            if (task_mode_daemon() < 0) {
                return (-1);
            }
            break;
	
        case ('f'):
            log_file = optarg;
            break;

        case ('g'):
            if (task_mode_log() < 0) {
                return (-1);
            }
            break;
				
        case ('i'):
            dif = IFACE_MANUAL;
            ddev = optarg;
            break;
				
        case ('o'):
            dif = IFACE_AUTO;
            break;
				
        case ('l'):
            dif = IFACE_LIST;
				
            if (iface_manager() < 0) {
                return (-1);
            }
				
            aprintf(stdout, 0, "\n");
            return (0);
				
        case ('c'):
            sarpi_cache_file = optarg;
	
            if (j == 2) {
                j = 3;
            } else {
                j = 1;
            }
            break;
				
        case ('x'):
            if (sarpi_set_timeout(optarg) < 0) {
                return (-1);
            }
	
            if (j == 2) {
                j = 3;
            } else {
                j = 1;
            }
            break;
				
        case ('S'):
            if (dinspec != INSPEC_NULL) {
                aprintf(stderr, 0, "ERROR: Can't use both DARPI and " \
                        "SARPI or HARPI on same interface!\n\n");

                return (-1);
            }
			
            dinspec = INSPEC_SARPI;
            break;
			
        case ('y'):
            if (darpi_set_timeout(optarg) < 0) {
                return (-1);
            }
			
            if (j == 1) {
                j = 3;
            } else {
                j = 2;	
            }
            break;
	
        case ('D'):
            if (dinspec != INSPEC_NULL) {
                aprintf(stderr, 0, "ERROR: Can't use both SARPI and " \
                        "DARPI or HARPI on same interface!\n\n");

                return (-1);
            }

            dinspec = INSPEC_DARPI;
            break;
                
        case ('H'):
            if (dinspec != INSPEC_NULL) {
                aprintf(stderr, 0, "ERROR: Can't use both HARPI and " \
                        "SARPI or DARPI on same interface!\n\n");
                    
                return (-1);
            }
                
            dinspec = INSPEC_HARPI;
            break;
				
        case ('e'):
            license();
            return (0);
	
        case ('v'):
            version();
            return (0);
	
        case ('h'):
            help();
            return (0);
	
        case (':'):
        case ('?'):
            aprintf(stderr, 0, "\n");
            return (-1);
				
        default:
            break;
        }
    }
    argc -= optind;
    argv += optind;
	
    if (dinspec == INSPEC_NULL) {
        if (j != 0) {
            switch (j) {
            case (1):
                aprintf(stderr, 0, "ERROR: SARPI required " \
                        "-S option to work!\n\n");				
                return (-1);
	
            case (2):
                aprintf(stderr, 0, "ERROR: DARPI required " \
                        "-D option to work!\n\n");
                return (-1);
                    
            case (3):
                aprintf(stderr, 0, "ERROR: HARPI required " \
                        "-H option to work!\n\n");
                return (-1);

            default:
                break;
            }
        } else {
            aprintf(stderr, 0, "ERROR: Choose SARPI, DARPI or HARPI!\n\n");

            return(-1);
        }
    } else {
        switch (dinspec) {
        case (INSPEC_SARPI):
            if (j == 2) {
                aprintf(stderr, 0, "ERROR: SARPI doesn't " \
                        "required DARPI options!\n\n");
                return (-1);
            }
            break;

        case (INSPEC_DARPI):
            if (j == 1) {
                aprintf(stderr, 0, "ERROR: DARPI doesn't " \
                        "required SARPI options!\n\n");
                return (-1);
            }
            break;

        case (INSPEC_HARPI):
        case (INSPEC_NULL):
        default:
            break;
        }
    }
	
    sigemptyset(&sigse);
    sigaddset(&sigse, SIGINT);
    sigaddset(&sigse, SIGTERM);
    sigaddset(&sigse, SIGQUIT);
    sigaddset(&sigse, SIGHUP);
    sigaddset(&sigse, SIGCONT);
	
    if (pthread_sigmask(SIG_BLOCK, &sigse, NULL) < 0) {
        ERROR(strerror(errno));
		
        return (-1);
    }
	
    if (main_start() < 0) {
        return (-1);
    }
	
    if (main_signal() < 0) {
        return (-1);
    }
	
    return (0);
}

/* 
 * EOF. 
 */ 
