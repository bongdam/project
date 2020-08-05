#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <string.h>

#include "udp.h"

int openPort( unsigned short port, unsigned int interfaceIp, int debug )
{
   int fd;
   struct sockaddr_in addr;

   fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
   if ( fd < 0)
   {
      perror("Could not create a UDP socket:");
      return INVALID_SOCKET;
   }

   memset((char*) &(addr),0, sizeof((addr)));
   addr.sin_family = AF_INET;
   addr.sin_addr.s_addr =INADDR_ANY;
   addr.sin_port = htons(port);

   if ( (interfaceIp != 0) &&
         ( interfaceIp != 0x100007f ) )
   {
      addr.sin_addr.s_addr = htonl(interfaceIp);
   }

   if ( bind( fd,(struct sockaddr*)&addr, sizeof(addr)) != 0 )
   {
      fprintf(stdout, "Bind(%08x) Error: %s\n", interfaceIp, strerror(errno));
      close(fd);
      fd = -1;
   }

   return fd;
}


int
getMessage( int fd, char* buf, int* len,
            unsigned int* srcIp, unsigned short* srcPort,
            int verbose)
{
   int originalSize = *len;
   struct sockaddr_in from;
   int fromLen = sizeof(from);

   *len = recvfrom(fd,
                   buf,
                   originalSize,
                   0,
                   (struct sockaddr *)&from,
                   (socklen_t*)&fromLen);

   if ( *len <= 0 )
   {
      fprintf(stdout, "recv eror :%s\n", strerror(errno));
      return 0;
   }

   if ( *len == 0 )
   {
      return 0;
   }

   *srcPort = ntohs(from.sin_port);
   *srcIp = ntohl(from.sin_addr.s_addr);

   if ( (*len)+1 >= originalSize )
   {
      return 0;
   }
   buf[*len]=0;

   return 1;
}


int
sendMessage( int fd, char* buf, int l,
             unsigned int dstIp, unsigned short dstPort,
             int verbose)
{
   int s;
   if ( dstPort == 0 )
   {
      // sending on a connected port
      s = send(fd,buf,l,0);
   }
   else
   {
      struct sockaddr_in to;
      int toLen = sizeof(to);
      memset(&to,0,toLen);

      to.sin_family = AF_INET;
      to.sin_port = htons(dstPort);
      to.sin_addr.s_addr = htonl(dstIp);

      s = sendto(fd, buf, l, 0,(struct sockaddr*)&to, toLen);
   }

   if ( s == 0 )
   {
      return 0;
   }

   if ( s != l )
   {
      return 0;
   }

   return 1;
}


