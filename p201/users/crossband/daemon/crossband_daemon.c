#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/wireless.h>

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <time.h>
#include <sys/time.h>
#include <signal.h>

#define SIOCROSSBANDSETMIB                 0x89f1 //set mib 0x89f1
#define SIOCROSSBANDGETMIB                0x89f2  // get mib
#define SIOCROSSBANDINFOREQ             0x8BFC //get information

#define PHYBAND_2G                     1
#define PHYBAND_5G                     2

#define INFO_RECORD_INTERVAL            1
#define PATH_SWITCH_INTERVAL            30

struct mibValue{
    unsigned char rssi_threshold;
    unsigned char cu_threshold;
    unsigned char noise_threshold;
    unsigned char rssi_weight;
    unsigned char cu_weight;
    unsigned char noise_weight;
};

#if 0 // tesia
struct envinfo_data{
    unsigned int rssi_metric;
    unsigned int cu_metric;
    unsigned int noise_metric;
};
#endif

static char *pidfile = "/var/run/crossband.pid";

const char *preferband_mib = "crossband_preferBand";
const char *cuThreshold_mib = "crossband_cuThreshold";
const char *rssiThreshold_mib = "crossband_rssiThreshold";
const char *noiseThreshold_mib = "crossband_noiseThreshold";
const char *cuWeight_mib = "crossband_cuWeight";
const char *rssiWeight_mib = "crossband_rssiWeight";
const char *noiseWeight_mib = "crossband_noiseWeight";

const char* wlan0_ifName = "wlan0";
const char* wlan1_ifName = "wlan1";

struct mibValue mibValueOf5G ={
    .rssi_threshold = 15,
    .cu_threshold = 150,
    .noise_threshold = 50,
    .rssi_weight = 2,
    .cu_weight = 3,
    .noise_weight = 2
    };

struct mibValue mibValueOf2G = {
    .rssi_threshold = 5,
    .cu_threshold = 100,
    .noise_threshold = 30,
    .rssi_weight = 4,
    .cu_weight = 12,
    .noise_weight = 5
    };

struct crossband_metric recordOf5G = {
    .rssi_metric = 0,
    .cu_metric = 0,
    .noise_metric = 0
    };

struct crossband_metric recordOf2G = {
    .rssi_metric = 0,
    .cu_metric = 0,
    .noise_metric = 0
    };

static unsigned int cross_band_index;
struct mibValue* mibValuePointer = &mibValueOf5G;
struct crossband_metric* envinfo_dataPointer = &recordOf5G;
unsigned char not_prefer = 0;
unsigned char prefer = 1;
unsigned char wlan0_is5G = 0;
unsigned char wlan1_is5G = 0;
unsigned int wlan0_bandRating = 0;
unsigned int wlan1_bandRating = 0;
unsigned char tempbuf[16384];


static int pidfile_acquire(char *pidfile)
{
    int pid_fd;

    if(pidfile == NULL)
        return -1;

    pid_fd = open(pidfile, O_CREAT | O_WRONLY, 0644);
    if (pid_fd < 0)
        printf("Unable to open pidfile %s\n", pidfile);
    else
        lockf(pid_fd, F_LOCK, 0);

    return pid_fd;
}

static void pidfile_write_release(int pid_fd)
{
    FILE *out;

    if(pid_fd < 0)
        return;

    if((out = fdopen(pid_fd, "w")) != NULL)
    {
        fprintf(out, "%d\n", getpid());
        fclose(out);
    }
    lockf(pid_fd, F_UNLCK, 0);
    close(pid_fd);
}

static int crossband_set_mib(const char *interfacename, const char *mibname, char value)
{
    int skfd;
    struct iwreq wrq;
    char tmp[30];

    sprintf(tmp, "%s=%d", mibname, value);

    if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) <0)
    {
        printf("[%s %d] socket error \n", __FUNCTION__, __LINE__);
        return -1;
    }

    /* Set device name */
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, interfacename, IFNAMSIZ);

    wrq.u.data.pointer = (caddr_t)tmp;
    wrq.u.data.length = strlen((char *)tmp)+1;

    /* Do the request */
    if(ioctl(skfd, SIOCROSSBANDSETMIB, &wrq) < 0)
    {
        printf("[%s %d] ioctl[SIOCROSSBANDSETMIB]", __FUNCTION__, __LINE__);
        close(skfd);
        return -1;
    }

    close(skfd);
    return 0;
}

static int crossband_get_mib(const char *interfacename , const char* mibname ,void *result,int size)
{
    int skfd;
    struct iwreq wrq;
    unsigned char tmp[30];

    if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) <0)
    {
        printf("[%s %d] socket error \n", __FUNCTION__, __LINE__);
        return -1;
    }

    /* Set device name */
    strcpy(wrq.ifr_name, interfacename);
    strcpy((char *)tmp,mibname);

    wrq.u.data.pointer = tmp;
    wrq.u.data.length = strlen((char *)tmp);

    /* Do the request */
    if(ioctl(skfd, SIOCROSSBANDGETMIB, &wrq) < 0)
    {
        printf("[%s %d] ioctl[SIOCROSSBANDGETMIB]", __FUNCTION__, __LINE__);
        close(skfd);
        return -1;
    }

    close(skfd);
    if(size)
    {
        memcpy(result,tmp, size);
    }
    else
        strcpy(result, (char *)tmp);
    return 0;
}

static int get_env_info(const char *ifname, struct crossband_metric* pointer)
{
    int sock;
    struct iwreq wrq;
    int ret = -1;
    int err;

    /*** Inizializzazione socket ***/
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        err = errno;
        printf("[%s %d]: Can't create socket for ioctl. %s(%d)", __FUNCTION__, __LINE__, ifname, err);
        goto out;
    }

    /*** Inizializzazione struttura iwreq ***/
    memset((void *)pointer, 0, sizeof(struct crossband_metric));
    strncpy(wrq.ifr_name, ifname, IFNAMSIZ);

    /*** give parameter and buffer ***/
    wrq.u.data.pointer = (caddr_t)pointer;
    wrq.u.data.length = sizeof(struct crossband_metric);

    /*** ioctl ***/
    if(ioctl(sock, SIOCROSSBANDINFOREQ, &wrq) < 0)
    {
        err = errno;
        printf("[%s %d]: ioctl Error.%s(%d)", __FUNCTION__, __LINE__, ifname, err);
        goto out;
    }
    ret = 0;

out:
    close(sock);
    return ret;
}

static int initialize_mibValues( const char* interfacename, struct mibValue* pointer)
{
    if(crossband_set_mib(interfacename, cuThreshold_mib, pointer->cu_threshold ) == -1 )
        goto error;
    if(crossband_set_mib(interfacename, noiseThreshold_mib, pointer->noise_threshold ) == -1 )
        goto error;
    if(crossband_set_mib(interfacename, rssiThreshold_mib, pointer->rssi_threshold ) == -1 )
        goto error;
    if(crossband_set_mib(interfacename, cuWeight_mib, pointer->cu_weight ) == -1 )
        goto error;
    if(crossband_set_mib(interfacename, rssiWeight_mib, pointer->rssi_weight ) == -1 )
        goto error;
    if(crossband_set_mib(interfacename, noiseWeight_mib, pointer->noise_weight ) == -1 )
        goto error;

error:
    return -1;
}

static int retrieve_mibValues( const char* interfacename, struct mibValue* pointer)
{
    if(crossband_get_mib(interfacename, cuThreshold_mib, &(pointer->cu_threshold), 1) == -1 )
        goto error;
    if(crossband_get_mib(interfacename, noiseThreshold_mib, &(pointer->noise_threshold), 1) == -1 )
        goto error;
    if(crossband_get_mib(interfacename, rssiThreshold_mib, &(pointer->rssi_threshold), 1) == -1 )
        goto error;
    if(crossband_get_mib(interfacename, cuWeight_mib, &(pointer->cu_weight), 1) == -1 )
        goto error;
    if(crossband_get_mib(interfacename, noiseWeight_mib, &(pointer->noise_weight), 1) == -1 )
        goto error;
    if(crossband_get_mib(interfacename, rssiWeight_mib, &(pointer->rssi_weight), 1) == -1 )
        goto error;

error:
    return -1;
}

static int calculate_bandrating(struct crossband_metric* data, struct mibValue* pointer, unsigned int* bandRating)
{

    unsigned int rssiScore = (data->rssi_metric < pointer->rssi_threshold)?(100 - data->rssi_metric)<<2:(100 - data->rssi_metric);
    unsigned int cuScore = (data->cu_metric > pointer->cu_threshold)?(data->cu_metric<<1):data->cu_metric;
    unsigned int noiseScore = (data->cu_metric > pointer->cu_threshold
        && data->noise_metric > pointer->noise_threshold)?data->noise_metric:0;

    *bandRating = (rssiScore * pointer->rssi_weight) + (cuScore * pointer->cu_weight) +
        (noiseScore * pointer->noise_weight);
}

static void do_daemon()
{
    printf("Crossband daemon - Started!\n");
    while (1)
    {
        
        sleep(INFO_RECORD_INTERVAL);

        cross_band_index++;
        
        if(cross_band_index >= PATH_SWITCH_INTERVAL)
        {
            
            if(wlan0_is5G){
                envinfo_dataPointer = &recordOf5G;
                get_env_info(wlan0_ifName, envinfo_dataPointer);
                mibValuePointer = &mibValueOf5G;
                retrieve_mibValues(wlan0_ifName, &mibValueOf5G);
                calculate_bandrating(envinfo_dataPointer, mibValuePointer, &(wlan0_bandRating));
                
                envinfo_dataPointer = &recordOf2G;
                get_env_info(wlan1_ifName, envinfo_dataPointer);
                mibValuePointer = &mibValueOf2G;
                retrieve_mibValues(wlan1_ifName, &mibValueOf2G);
                calculate_bandrating(envinfo_dataPointer, mibValuePointer, &(wlan1_bandRating));

            }
            else{
                envinfo_dataPointer = &recordOf2G;
                get_env_info(wlan0_ifName, envinfo_dataPointer);
                mibValuePointer = &mibValueOf2G;
                retrieve_mibValues(wlan0_ifName, &mibValueOf2G);
                calculate_bandrating(envinfo_dataPointer, mibValuePointer, &(wlan0_bandRating));
                
                envinfo_dataPointer = &recordOf5G;
                get_env_info(wlan1_ifName, envinfo_dataPointer);
                mibValuePointer = &mibValueOf5G;
                retrieve_mibValues(wlan1_ifName, &mibValueOf5G);
                calculate_bandrating(envinfo_dataPointer, mibValuePointer, &(wlan1_bandRating));
            }
#if 1            
            printf("5G\n");
            printf("rssiT:%u cuT:%u noiseT:%u\n", mibValueOf5G.rssi_threshold, mibValueOf5G.cu_threshold, mibValueOf5G.noise_threshold);
            printf("rssiW:%u cuW:%u noiseW:%u\n", mibValueOf5G.rssi_weight, mibValueOf5G.cu_weight, mibValueOf5G.noise_weight);
            printf("rssiM:%u cuM:%u noiseM:%u\n\n", recordOf5G.rssi_metric, recordOf5G.cu_metric, recordOf5G.noise_metric);

            printf("2G\n");
            printf("rssiT:%u cuT:%u noiseT:%u\n", mibValueOf2G.rssi_threshold, mibValueOf2G.cu_threshold, mibValueOf2G.noise_threshold);
            printf("rssiW:%u cuW:%u noiseW:%u\n", mibValueOf2G.rssi_weight, mibValueOf2G.cu_weight, mibValueOf2G.noise_weight);
            printf("rssiM:%u cuM:%u noiseM:%u\n\n", recordOf2G.rssi_metric, recordOf2G.cu_metric, recordOf2G.noise_metric);

            printf("wlan0 interface band rating: %u\n", wlan0_bandRating);
            printf("wlan1 interface band rating: %u\n\n", wlan1_bandRating);
#endif
            if(wlan0_bandRating < wlan1_bandRating){
                crossband_set_mib(wlan0_ifName, preferband_mib, prefer);
                crossband_set_mib(wlan1_ifName, preferband_mib, not_prefer);
            }
            else{
                crossband_set_mib(wlan0_ifName, preferband_mib, not_prefer);
                crossband_set_mib(wlan1_ifName, preferband_mib, prefer);
            }
                
            cross_band_index = 0;

        }
    }
}

int main(int argc, char *argv[])
{

    
    crossband_get_mib(wlan0_ifName, "phyBandSelect", &wlan0_is5G, 1);
    crossband_get_mib(wlan1_ifName, "phyBandSelect", &wlan1_is5G, 1);

	if(wlan0_is5G == PHYBAND_5G){
        //initialize 5GHz mib for wlan0
        initialize_mibValues(wlan0_ifName, &mibValueOf5G);
        //initialize 2.4GHz mib for wlan1
        initialize_mibValues(wlan1_ifName, &mibValueOf2G);
	}
	else if(wlan1_is5G == PHYBAND_5G){
        //initialize 5GHz mib for wlan1
        initialize_mibValues(wlan1_ifName, &mibValueOf5G);
        //initialize 2.4GHz mib for wlan0
        initialize_mibValues(wlan0_ifName, &mibValueOf2G);
	}
	else
		return 0;

	printf("Crossband daemon - Mib initialization successful\n");

    cross_band_index = 0;
    wlan0_bandRating = 0;
    wlan1_bandRating = 0;
    // destroy old process and create a PID file
    {
        int pid_fd;
        FILE *fp;
        char line[20];
        pid_t pid;

        if ((fp = fopen(pidfile, "r")) != NULL) {
            fgets(line, sizeof(line), fp);
            if (sscanf(line, "%d", &pid)) {
                if (pid > 1)
                    kill(pid, SIGTERM);
            }
            fclose(fp);
        }
        pid_fd = pidfile_acquire(pidfile);
        if (pid_fd < 0)
            return 0;

        if (daemon(0,1) == -1) {        
            printf("fork crossband error!\n");
            exit(1);
        }
        pidfile_write_release(pid_fd);
    }
    
    do_daemon();
out:
    return 0;
}
