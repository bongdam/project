#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <net/if.h>
#include <bcmnvram.h>
#include <syslog.h>
#include <hanguel.h>

#define NOSSL

#include <shutils.h>
#include "cwmpGlobal.h"
#include "bcm_param_api.h"
#include "udp.h"
#include "stun.h"

#ifndef false
#define false 0
#endif

#ifndef true
#define true 1
#endif

static StunAddress4	wAddr;
static StunAddress4	stunServerAddr;
static int SrcPort=0;

static void
computeHmac(char* hmac, const char* input, int length, const char* key, int keySize);

static int
stunParseAtrAddress( char* body, unsigned int hdrLen,  StunAtrAddress4 *result )
{
   if ( hdrLen != 8 )
   {
      fprintf(stdout, "hdrLen wrong for Address\n");
      return false;
   }
   result->pad = *body++;
   result->family = *body++;
   if (result->family == IPv4Family)
   {
      uint16 nport;
      memcpy(&nport, body, 2);
      body+=2;
      result->ipv4.port = ntohs(nport);

      uint32 naddr;
      memcpy(&naddr, body, 4);
      body+=4;
      result->ipv4.addr = ntohl(naddr);
      return true;
   }
   else if (result->family == IPv6Family)
   {
   }
   else
   {
   }

   return false;
}

static int
stunParseAtrChangeRequest( char* body, unsigned int hdrLen,  StunAtrChangeRequest *result )
{
   if ( hdrLen != 4 )
   {
      fprintf(stdout, "hdr length = %d expecting %d", hdrLen, sizeof(result));
      fprintf(stdout, "Incorrect size for ChangeRequest\n");
      return false;
   }
   else
   {
      memcpy(&result->value, body, 4);
      result->value = ntohl(result->value);
      return true;
   }
}

static bool
stunParseAtrError( char* body, unsigned int hdrLen,  StunAtrError result )
{
   if ( hdrLen >= sizeof(result) )
   {
      fprintf(stdout, "head on Error too large\n");
      return false;
   }
   else
   {
      memcpy(&result.pad, body, 2);
      body+=2;
      result.pad = ntohs(result.pad);
      result.errorClass = *body++;
      result.number = *body++;

      result.sizeReason = hdrLen - 4;
      memcpy(&result.reason, body, result.sizeReason);
      result.reason[result.sizeReason] = 0;
      return true;
   }
}

static bool
stunParseAtrUnknown( char* body, unsigned int hdrLen,  StunAtrUnknown result )
{
   if ( hdrLen >= sizeof(result) )
   {
      return false;
   }
   else
   {
      int i;
      if (hdrLen % 4 != 0) return false;
      result.numAttributes = hdrLen / 4;
      for (i=0; i<result.numAttributes; i++)
      {
         memcpy(&result.attrType[i], body, 2);
         body+=2;
         result.attrType[i] = ntohs(result.attrType[i]);
      }
      return true;
   }
}


static bool
stunParseAtrString( char* body, unsigned int hdrLen,  StunAtrString *result )
{
   if ( hdrLen >= STUN_MAX_STRING )
   {
      fprintf(stdout, "String is too large\n");
      return false;
   }
   else
   {
      if (hdrLen % 4 != 0)
      {
         fprintf(stdout, "Bad length string =%d\n ", hdrLen);
         return false;
      }

      result->sizeValue = hdrLen;
      memcpy(&result->value, body, hdrLen);
      result->value[hdrLen] = 0;
      return true;
   }
}


static bool
stunParseAtrIntegrity( char* body, unsigned int hdrLen,  StunAtrIntegrity *result )
{
   if ( hdrLen != 20)
   {
      fprintf(stdout, "MessageIntegrity must be 20 bytes\n");
      return false;
   }
   else
   {
      memcpy(&result->hash, body, hdrLen);
      return true;
   }
}


int
stunParseMessage( char* buf, unsigned int bufLen, StunMessage *msg, int verbose)
{
   char *body;
   unsigned int size;

   memset(msg, 0, sizeof(StunMessage));

   if (sizeof(StunMsgHdr) > bufLen)
   {
      fprintf(stdout, "Bad message\n");
      return false;
   }

   memcpy(&msg->msgHdr, buf, sizeof(StunMsgHdr));
   msg->msgHdr.msgType = ntohs(msg->msgHdr.msgType);
   msg->msgHdr.msgLength = ntohs(msg->msgHdr.msgLength);

   if (msg->msgHdr.msgLength + sizeof(StunMsgHdr) != bufLen)
   {
      fprintf(stdout, "Message header length doesn't match message size: %d-%d\n", msg->msgHdr.msgLength, bufLen);
      return false;
   }

   body = buf + sizeof(StunMsgHdr);
   size = msg->msgHdr.msgLength;

   //fprintf(stdout, "bytes after header = " << size);

   while ( size > 0 )
   {
      // !jf! should check that there are enough bytes left in the buffer

      StunAtrHdr* attr = (StunAtrHdr *)(body);

      unsigned int attrLen = ntohs(attr->length);
      int atrType = ntohs(attr->type);

      if ( attrLen+4 > size )
      {
         fprintf(stdout, "claims attribute is larger than size of message "
                 "(attribute type=%02x)\n", atrType);
         return false;
      }

      body += 4; // skip the length and type in attribute header
      size -= 4;

      switch ( atrType )
      {
      case MappedAddress:
         msg->hasMappedAddress = true;
         if ( stunParseAtrAddress(  body,  attrLen,  &msg->mappedAddress )== false )
         {
            fprintf(stdout, "problem parsing MappedAddress\n");
            return false;
         }
         else
         {
         }

         break;

      case ResponseAddress:
         msg->hasResponseAddress = true;
         if ( stunParseAtrAddress(  body,  attrLen,  &msg->responseAddress )== false )
         {
            fprintf(stdout, "problem parsing ResponseAddress\n");
            return false;
         }
         else
         {
         }
         break;

      case ChangeRequest:
         msg->hasChangeRequest = true;
         if (stunParseAtrChangeRequest( body, attrLen, &msg->changeRequest) == false)
         {
            fprintf(stdout, "problem parsing ChangeRequest\n");
            return false;
         }
         else
         {
         }
         break;

      case SourceAddress:
         msg->hasSourceAddress = true;
         if ( stunParseAtrAddress(  body,  attrLen,  &msg->sourceAddress )== false )
         {
            fprintf(stdout, "problem parsing SourceAddress\n");
            return false;
         }
         else
         {
         }
         break;

      case ChangedAddress:
         msg->hasChangedAddress = true;
         if ( stunParseAtrAddress(  body,  attrLen,  &msg->changedAddress )== false )
         {
            fprintf(stdout, "problem parsing ChangedAddress\n");
            return false;
         }
         else
         {
         }
         break;

      case Username:
         msg->hasUsername = true;
         if (stunParseAtrString( body, attrLen, &msg->username) == false)
         {
            fprintf(stdout, "problem parsing Username");
            return false;
         }
         else
         {
            fprintf(stdout, "Username = %s\n", msg->username.value);
         }

         break;

      case Password:
         msg->hasPassword = true;
         if (stunParseAtrString( body, attrLen, &msg->password) == false)
         {
            fprintf(stdout, "problem parsing Password\n");
            return false;
         }
         else
         {
            fprintf(stdout, "Password = %s\n", msg->password.value);
         }
         break;

      case MessageIntegrity:
         msg->hasMessageIntegrity = true;
         if (stunParseAtrIntegrity( body, attrLen, &msg->messageIntegrity) == false)
         {
            fprintf(stdout, "problem parsing MessageIntegrity\n");
            return false;
         }
         else
         {
            //if (verbose) fprintf(stdout, "MessageIntegrity = " << msg.messageIntegrity.hash);
         }

         // read the current HMAC
         // look up the password given the user of given the transaction id
         // compute the HMAC on the buffer
         // decide if they match or not
         break;

      case ErrorCode:
         msg->hasErrorCode = true;
         if (stunParseAtrError(body, attrLen, msg->errorCode) == false)
         {
            fprintf(stdout, "problem parsing ErrorCode\n");
            return false;
         }
         else
         {
            fprintf(stdout, "ErrorCode = %d %d %s\n", msg->errorCode.errorClass
                    , msg->errorCode.number
                    , msg->errorCode.reason);
         }

         break;

      case UnknownAttribute:
         msg->hasUnknownAttributes = true;
         if (stunParseAtrUnknown(body, attrLen, msg->unknownAttributes) == false)
         {
            fprintf(stdout, "problem parsing UnknownAttribute\n");
            return false;
         }
         break;

      case ReflectedFrom:
         msg->hasReflectedFrom = true;
         if ( stunParseAtrAddress(  body,  attrLen,  &msg->reflectedFrom ) == false )
         {
            fprintf(stdout, "problem parsing ReflectedFrom\n");
            return false;
         }
         break;

      case XorMappedAddress:
         msg->hasXorMappedAddress = true;
         if ( stunParseAtrAddress(  body,  attrLen,  &msg->xorMappedAddress ) == false )
         {
            fprintf(stdout, "problem parsing XorMappedAddress\n");
            return false;
         }
         else
         {
            fprintf(stdout, "XorMappedAddress = %08x\n", msg->mappedAddress.ipv4.addr);
         }
         break;

      case XorOnly:
         msg->xorOnly = true;
         fprintf(stdout, "xorOnly = true\n");
         break;

      case ServerName:
         msg->hasServerName = true;
         if (stunParseAtrString( body, attrLen, &msg->serverName) == false)
         {
            fprintf(stdout, "problem parsing ServerName\n");
            return false;
         }
         else
         {
            fprintf(stdout, "ServerName = %s", msg->serverName.value);
         }
         break;

      case SecondaryAddress:
         msg->hasSecondaryAddress = true;
         if ( stunParseAtrAddress(  body,  attrLen,  &msg->secondaryAddress ) == false )
         {
            fprintf(stdout, "problem parsing secondaryAddress\n");
            return false;
         }
         else
         {
            fprintf(stdout, "SecondaryAddress = %08x\n", msg->secondaryAddress.ipv4.addr);
         }
         break;

      default:
         fprintf(stdout, "Unknown attribute: %04x\n", atrType);
         if ( atrType <= 0x7FFF )
         {
            return false;
         }
      }

      body += attrLen;
      size -= attrLen;
   }

   return true;
}


static char*
encode16(char* buf, uint16 data)
{
   uint16 ndata = htons(data);
   memcpy(buf, (&ndata), sizeof(uint16));
   return buf + sizeof(uint16);
}

static char*
encode32(char* buf, uint32 data)
{
   uint32 ndata = htonl(data);
   memcpy(buf, (void*)(&ndata), sizeof(uint32));
   return buf + sizeof(uint32);
}


static char*
encode(char* buf, const char* data, unsigned int length)
{
   memcpy(buf, data, length);
   return buf + length;
}


static char*
encodeAtrAddress4(char* ptr, uint16 type, const StunAtrAddress4 atr)
{
   ptr = encode16(ptr, type);
   ptr = encode16(ptr, 8);
   *ptr++ = atr.pad;
   *ptr++ = IPv4Family;
   ptr = encode16(ptr, atr.ipv4.port);
   ptr = encode32(ptr, atr.ipv4.addr);

   return ptr;
}

static char*
encodeAtrChangeRequest(char* ptr, const StunAtrChangeRequest atr)
{
   ptr = encode16(ptr, ChangeRequest);
   ptr = encode16(ptr, 4);
   ptr = encode32(ptr, atr.value);
   return ptr;
}

static char*
encodeAtrError(char* ptr, const StunAtrError atr)
{
   ptr = encode16(ptr, ErrorCode);
   ptr = encode16(ptr, 6 + atr.sizeReason);
   ptr = encode16(ptr, atr.pad);
   *ptr++ = atr.errorClass;
   *ptr++ = atr.number;
   ptr = encode(ptr, atr.reason, atr.sizeReason);
   return ptr;
}


static char*
encodeAtrUnknown(char* ptr, const StunAtrUnknown atr)
{
   int i;

   ptr = encode16(ptr, UnknownAttribute);
   ptr = encode16(ptr, 2+2*atr.numAttributes);
   for (i=0; i<atr.numAttributes; i++)
   {
      ptr = encode16(ptr, atr.attrType[i]);
   }
   return ptr;
}


static char*
encodeXorOnly(char* ptr)
{
   ptr = encode16(ptr, XorOnly );
   return ptr;
}


static char*
encodeAtrString(char* ptr, uint16 type, const StunAtrString atr)
{
   ptr = encode16(ptr, type);
   ptr = encode16(ptr, atr.sizeValue);
   ptr = encode(ptr, atr.value, atr.sizeValue);
   return ptr;
}


static char*
encodeAtrIntegrity(char* ptr, const StunAtrIntegrity atr)
{
   ptr = encode16(ptr, MessageIntegrity);
   ptr = encode16(ptr, 20);
   ptr = encode(ptr, atr.hash, sizeof(atr.hash));
   return ptr;
}


unsigned int
stunEncodeMessage( const StunMessage msg,
                   char* buf,
                   unsigned int bufLen,
                   const StunAtrString password,
                   int verbose)
{
   char* ptr = buf;

   ptr = encode16(ptr, msg.msgHdr.msgType);
   char* lengthp = ptr;
   ptr = encode16(ptr, 0);
   ptr = encode(ptr, (const char*)(msg.msgHdr.id.octet), sizeof(msg.msgHdr.id));

   if (verbose) fprintf(stdout, "Encoding stun message: ");
   if (msg.hasMappedAddress)
   {
      if (verbose) fprintf(stdout, "Encoding MappedAddress: %08x", msg.mappedAddress.ipv4.addr);
      ptr = encodeAtrAddress4 (ptr, MappedAddress, msg.mappedAddress);
   }
   if (msg.hasResponseAddress)
   {
      if (verbose) fprintf(stdout, "Encoding ResponseAddress: %08x", msg.responseAddress.ipv4.addr);
      ptr = encodeAtrAddress4(ptr, ResponseAddress, msg.responseAddress);
   }
   if (msg.hasChangeRequest)
   {
      if (verbose) fprintf(stdout, "Encoding ChangeRequest: %d", msg.changeRequest.value);
      ptr = encodeAtrChangeRequest(ptr, msg.changeRequest);
   }
   if (msg.hasSourceAddress)
   {
      if (verbose) fprintf(stdout, "Encoding SourceAddress: %08x", msg.sourceAddress.ipv4.addr);
      ptr = encodeAtrAddress4(ptr, SourceAddress, msg.sourceAddress);
   }
   if (msg.hasChangedAddress)
   {
      if (verbose) fprintf(stdout, "Encoding ChangedAddress: %08x", msg.changedAddress.ipv4.addr);
      ptr = encodeAtrAddress4(ptr, ChangedAddress, msg.changedAddress);
   }
   if (msg.hasUsername)
   {
      if (verbose) fprintf(stdout, "Encoding Username: %s", msg.username.value);
      ptr = encodeAtrString(ptr, Username, msg.username);
   }
   if (msg.hasPassword)
   {
      if (verbose) fprintf(stdout, "Encoding Password: %s", msg.password.value);
      ptr = encodeAtrString(ptr, Password, msg.password);
   }
   if (msg.hasErrorCode)
   {
      if (verbose) fprintf(stdout, "Encoding ErrorCode: class= %d number=%d reason=%s"
                              , msg.errorCode.errorClass
                              , msg.errorCode.number
                              , msg.errorCode.reason);

      ptr = encodeAtrError(ptr, msg.errorCode);
   }
   if (msg.hasUnknownAttributes)
   {
      if (verbose) fprintf(stdout, "Encoding UnknownAttribute: ???");
      ptr = encodeAtrUnknown(ptr, msg.unknownAttributes);
   }
   if (msg.hasReflectedFrom)
   {
      if (verbose) fprintf(stdout, "Encoding ReflectedFrom: %08x", msg.reflectedFrom.ipv4.addr);
      ptr = encodeAtrAddress4(ptr, ReflectedFrom, msg.reflectedFrom);
   }
   if (msg.hasXorMappedAddress)
   {
      if (verbose) fprintf(stdout, "Encoding XorMappedAddress: %08x", msg.xorMappedAddress.ipv4.addr);
      ptr = encodeAtrAddress4 (ptr, XorMappedAddress, msg.xorMappedAddress);
   }
   if (msg.xorOnly)
   {
      if (verbose) fprintf(stdout, "Encoding xorOnly: ");
      ptr = encodeXorOnly( ptr );
   }
   if (msg.hasServerName)
   {
      if (verbose) fprintf(stdout, "Encoding ServerName: %s", msg.serverName.value);
      ptr = encodeAtrString(ptr, ServerName, msg.serverName);
   }
   if (msg.hasSecondaryAddress)
   {
      if (verbose) fprintf(stdout, "Encoding SecondaryAddress: %08x", msg.secondaryAddress.ipv4.addr);
      ptr = encodeAtrAddress4 (ptr, SecondaryAddress, msg.secondaryAddress);
   }

   if (password.sizeValue > 0)
   {
      if (verbose) fprintf(stdout, "HMAC with password: %s", password.value);

      StunAtrIntegrity integrity;
      computeHmac(integrity.hash, buf, (int)(ptr-buf) , password.value, password.sizeValue);
      ptr = encodeAtrIntegrity(ptr, integrity);
   }
   if (verbose) fprintf(stdout, "\n");

   encode16(lengthp, (uint16)(ptr - buf - sizeof(StunMsgHdr)));
   return (int)(ptr - buf);
}

int
stunRand()
{
   int fd;
   int rand64;

   fd = open("/dev/urandom", O_RDONLY|O_NONBLOCK);
   if (fd >= 0)
   {
      read(fd, &rand64, sizeof(int));
      close(fd);
   }
   else
   {
      static long seed=0;
      time_t t = time(NULL);
      unsigned char e[6];
      char tt[32];

      if (seed==0)
      {
         get_wan_macaddr(tt, sizeof(tt), LOWER);
         ether_atoe(tt, e);
         seed = e[2]*0x1000000 + e[3]*0x10000 + e[4]+0x100 + e[5];
         seed = ((seed<<8) ^ t)&0x7fffffff;
         srand(seed);
      }
      rand64 = rand();
   }
   return rand64;

}


/// return a random number to use as a port
int
stunRandomPort()
{
   int min=0x4000;
   int max=0x7FFF;

   int ret = stunRand();
   ret = ret|min;
   ret = ret&max;

//   printf("random port=%d\n", ret);
   return ret;
}


#ifdef NOSSL
static void
computeHmac(char* hmac, const char* input, int length, const char* key, int sizeKey)
{
   strncpy(hmac,"hmac-not-implemented",20);
}
#else
#include <openssl/hmac.h>

static void
computeHmac(char* hmac, const char* input, int length, const char* key, int sizeKey)
{
   unsigned int resultSize=0;
   HMAC(EVP_sha1(),
        key, sizeKey,
        (const unsigned char*)(input), length,
        (unsigned char*)(hmac), &resultSize);
}
#endif


static void
toHex(const char* buffer, int bufferSize, char* output)
{
   static char hexmap[] = "0123456789abcdef";
   int i;
   const char* p = buffer;
   char* r = output;

   for (i=0; i < bufferSize; i++)
   {
      unsigned char temp = *p++;

      int hi = (temp & 0xf0)>>4;
      int low = (temp & 0xf);

      *r++ = hexmap[hi];
      *r++ = hexmap[low];
   }
   *r = 0;
}


uint64
stunGetSystemTimeSecs()
{
   uint64 time=0;
   struct timeval now;
   gettimeofday( &now , NULL );
   time = now.tv_sec;
   return time;
}


// returns true if it scucceeded
int
stunParseHostName( char* peerName,
                   uint32 *ip,
                   uint16 *portVal,
                   uint16 defaultPort )
{
   struct in_addr sin_addr;
   char host[512];
   char* port = NULL;
   struct hostent* h;
   int portNum = defaultPort;

   // pull out the port part if present.
   char* sep;

   strncpy(host,peerName,512);
   host[512-1]='\0';

   sep = strchr(host, ':');
   if ( sep == NULL )
   {
      portNum = defaultPort;
   }
   else
   {
      char* endPtr=NULL;

      *sep = 0;

      port = sep + 1;
      portNum = strtol(port,&endPtr,10);

      if ( endPtr != NULL )
      {
         if ( *endPtr != 0 )
         {
            portNum = defaultPort;
         }
      }
   }

   if ( portNum < 1024 ) return false;
   if ( portNum >= 0xFFFF ) return false;

   printf("%s:%d Host->%s, port=%d\n", __FUNCTION__, __LINE__, host, portNum);
   // figure out the host part
   h = gethostbyname( host );
   if ( h == NULL )
   {
      *ip = INADDR_ANY;
      return false;
   }
   else
   {
      sin_addr = *(struct in_addr*)h->h_addr;
      *ip = ntohl( sin_addr.s_addr );
   }
   *portVal = portNum;

   return true;
}


int
stunParseServerName( char* name, StunAddress4 *addr)
{
   int ret;

   // TODO - put in DNS SRV stuff.

   ret = stunParseHostName( name, &addr->addr, &addr->port, 3478);
   if ( ret != true )
   {
      addr->port=0xFFFF;
   }
   return ret;
}

#if 0
static void
stunCreateErrorResponse(StunMessage *response, int cl, int number, const char* msg)
{
   response->msgHdr.msgType = BindErrorResponseMsg;
   response->hasErrorCode = true;
   response->errorCode.errorClass = cl;
   response->errorCode.number = number;
   snprintf(response->errorCode.reason, sizeof(response->errorCode.reason), "%s", msg);
}

static void
stunCreateSharedSecretErrorResponse(StunMessage& response, int cl, int number, const char* msg)
{
   response.msgHdr.msgType = SharedSecretErrorResponseMsg;
   response.hasErrorCode = true;
   response.errorCode.errorClass = cl;
   response.errorCode.number = number;
   snprintf(response.errorCode.reason, sizeof(response.errorCode.reason), "%s", msg);
}

static void
stunCreateSharedSecretResponse(const StunMessage request, const StunAddress4 source, StunMessage *response)
{
   response->msgHdr.msgType = SharedSecretResponseMsg;
   response->msgHdr.id = request.msgHdr.id;

   response->hasUsername = true;
   stunCreateUserName( source, &response->username);

   response->hasPassword = true;
   stunCreatePassword( response->username, &response->password);
}
#endif

int
stunFindLocalInterfaces(uint32* addresses,int maxRet)
{
#if defined(WIN32) || defined(__sparc__)
   return 0;
#else
   struct ifconf ifc;

   int s = socket( AF_INET, SOCK_DGRAM, 0 );
   int len = 100 * sizeof(struct ifreq);

   char buf[ len ];

   ifc.ifc_len = len;
   ifc.ifc_buf = buf;

   int e = ioctl(s,SIOCGIFCONF,&ifc);
   char *ptr = buf;
   int tl = ifc.ifc_len;
   int count=0;

   while ( (tl > 0) && ( count < maxRet) )
   {
      struct ifreq* ifr = (struct ifreq *)ptr;

      int si = sizeof(ifr->ifr_name) + sizeof(struct sockaddr);
      tl -= si;
      ptr += si;
      //char* name = ifr->ifr_ifrn.ifrn_name;
      //cerr << "name = " << name);

      struct ifreq ifr2;
      ifr2 = *ifr;

      e = ioctl(s,SIOCGIFADDR,&ifr2);
      if ( e == -1 )
      {
         break;
      }

      //cerr << "ioctl addr e = " << e);

      struct sockaddr a = ifr2.ifr_addr;
      struct sockaddr_in* addr = (struct sockaddr_in*) &a;

      uint32 ai = ntohl( addr->sin_addr.s_addr );
      if (((ai>>24)&0xFF) != 127)
      {
         addresses[count++] = ai;
      }

#if 0
      cerr << "Detected interface "
           << int((ai>>24)&0xFF) << "."
           << int((ai>>16)&0xFF) << "."
           << int((ai>> 8)&0xFF) << "."
           << int((ai    )&0xFF);
#endif
   }

   close(s);

   return count;
#endif
}


void
stunBuildReqSimple( StunMessage* msg,
                    const StunAtrString username,
                    int changePort, int changeIp, unsigned int id )
{
   int i;
   memset( msg , 0 , sizeof(*msg) );

   msg->msgHdr.msgType = BindRequestMsg;

   for (i=0; i<16; i=i+4 )
   {
      int r = stunRand();
      msg->msgHdr.id.octet[i+0]= r>>0;
      msg->msgHdr.id.octet[i+1]= r>>8;
      msg->msgHdr.id.octet[i+2]= r>>16;
      msg->msgHdr.id.octet[i+3]= r>>24;
   }

   if ( id != 0 )
   {
      msg->msgHdr.id.octet[0] = id;
   }

   msg->hasChangeRequest = true;
   msg->changeRequest.value =(changeIp?ChangeIpFlag:0) |
                             (changePort?ChangePortFlag:0);

   if ( username.sizeValue > 0 )
   {
      msg->hasUsername = true;
      msg->username = username;
   }
}

void
stunCreateUserName(const StunAddress4 source, StunAtrString* username)
{
   uint64 ti = time(NULL);
   uint32 lotime;
   char buffer[1024];
   char tmp[1024] = "";
   char hmac[20];
   char key[] = "Jason";
   char hmacHex[41];
   int l;

   ti -= (ti % 20*60);
   lotime = ti & 0xFFFFFFFF;
   snprintf(buffer, sizeof(buffer), 
           "%08x:%08x:%08x:", source.addr,
           stunRand(),
           lotime);
   computeHmac(hmac, buffer, STRLEN(buffer), key, STRLEN(key) );
   toHex(hmac, 20, hmacHex );
   hmacHex[40] =0;

   strncat_r(buffer, hmacHex, tmp, sizeof(tmp));

   l = STRLEN(tmp);

   username->sizeValue = l;
   memcpy(username->value,tmp,l);
   username->value[l]=0;

   //if (verbose) clog << "computed username=" << username.value << endl;
}

void
stunCreatePassword(const StunAtrString username, StunAtrString* password)
{
   char hmac[20];
   char key[] = "Fluffy";
   //char buffer[STUN_MAX_STRING];
   computeHmac(hmac, username.value, STRLEN(username.value), key, STRLEN(key));
   toHex(hmac, 20, password->value);
   password->sizeValue = 40;
   password->value[40]=0;

   //clog << "password=" << password->value << endl;
}



static void
stunSendTest( Socket myFd, StunAddress4 dest,
              const StunAtrString username, const StunAtrString password,
              int testNum, bool verbose )
{
   bool changePort=false;
   bool changeIP=false;
   bool discard=false;
   StunMessage req;
   char buf[STUN_MAX_MESSAGE_SIZE];
   int len = STUN_MAX_MESSAGE_SIZE;

//	fprintf(stdout, "Dest IP Address:%08x Port=%d\n", dest.addr, dest.port );
   switch (testNum)
   {
   case 1:
   case 10:
   case 11:
      break;
   case 2:
      //changePort=true;
      changeIP=true;
      break;
   case 3:
      changePort=true;
      break;
   case 4:
      changeIP=true;
      break;
   case 5:
      discard=true;
      break;
   default:
      fprintf(stdout, "Unknown Test Num=%d\n", testNum);
   }

   memset(&req, 0, sizeof(StunMessage));

   stunBuildReqSimple( &req, username,
                       changePort , changeIP ,
                       testNum );

   len = stunEncodeMessage( req, buf, len, password,verbose );

   if ( verbose )
   {
      fprintf(stdout, "About to send msg of len %d to %08x\n", len, dest.addr);
   }

   sendMessage( myFd, buf, len, dest.addr, dest.port, verbose );

   usleep(10*1000);
}


void
stunGetUserNameAndPassword(  const StunAddress4 dest,
                             StunAtrString* username,
                             StunAtrString* password)
{
   // !cj! This is totally bogus - need to make TLS connection to dest and get a
   // username and password to use
   stunCreateUserName(dest, username);
   stunCreatePassword(*username, password);
}

NatType
stunNatType( StunAddress4 dest,
             int verbose,
             int* preservePort, // if set, is return for if NAT preservers ports or not
             int* hairpin,  // if set, is the return for if NAT will hairpin packets
             int port, // port to use for the test, 0 to choose random port
             int *publicIp,
             unsigned short *mappedPort
           )
{
   bool respTestI=false;
   bool isNat=true;
   bool	respTestPreservePort=false;

   StunAddress4 testIchangedAddr;
   StunAddress4 testImappedAddr;
   StunAddress4 testI2dest=dest;

   struct in_addr map_ip;

   uint32 interfaceIp=0;
   int count=0;
   Socket myFd1 = openPort(port,interfaceIp,verbose);
   Socket myFd2 = openPort(port+1,interfaceIp,verbose);

//	fprintf(stdout, "Dest IP Address:%08x Port=%d\n", dest.addr, dest.port );
   if ( hairpin )
   {
      *hairpin = false;
   }

   if ( port == 0 )
   {
      port = stunRandomPort();
   }

   if ( ( myFd1 == INVALID_SOCKET) || ( myFd2 == INVALID_SOCKET) )
   {
      fprintf(stdout, "Some problem opening port/interface to send on\n");
      return StunTypeFailure;
   }

   memset(&testImappedAddr,0,sizeof(testImappedAddr));

   StunAtrString username;
   StunAtrString password;

   username.sizeValue = 0;
   password.sizeValue = 0;

#ifdef USE_TLS
   stunGetUserNameAndPassword( dest, username, password );
#endif

   if ( !respTestI )
   {
      syslog(LOG_INFO, DVLOG_MARK_ADMIN "Binding-Request " H_SEND);
	  TLOG_PRINT("STUN : Send Binding Request(%hu)\n", port);
      stunSendTest( myFd1, dest, username, password, 1 ,verbose );
   }
   while ( count < 5 && respTestI==false)
   {
      struct timeval tv;
      fd_set fdSet;
      int fdSetSize;

      FD_ZERO(&fdSet);
      fdSetSize=0;
      FD_SET(myFd1,&fdSet);
      fdSetSize = (myFd1+1>fdSetSize) ? myFd1+1 : fdSetSize;
      FD_SET(myFd2,&fdSet);
      fdSetSize = (myFd2+1>fdSetSize) ? myFd2+1 : fdSetSize;
      tv.tv_sec=2;
      tv.tv_usec=150*1000; // 150 ms
      if ( count == 0 ) tv.tv_usec=0;

      int  err = select(fdSetSize, &fdSet, NULL, NULL, &tv);
      if ( err < 0)
      {
         // error occured
         fprintf(stdout, "Error: %s in select", strerror(errno));
         return StunTypeFailure;
      }
      else if ( err == 0 )
      {
         // timeout occured
         count++;

         if ( !respTestI )
         {
            syslog(LOG_INFO, DVLOG_MARK_ADMIN "Binding-Request " H_SEND);
	  		TLOG_PRINT("STUN : Send Binding Request(%hu)\n", port);
            stunSendTest( myFd1, dest, username, password, 1 ,verbose );
         }

      }
      else
      {
         int i;
         //if (verbose) fprintf(stdout, "-----------------------------------------");
         // data is avialbe on some fd

         for (i=0; i<2; i++)
         {
            Socket myFd;
            if ( i==0 )
            {
               myFd=myFd1;
            }
            else
            {
               myFd=myFd2;
            }

            if ( myFd!=INVALID_SOCKET )
            {
               if ( FD_ISSET(myFd,&fdSet) )
               {
                  char msg[STUN_MAX_MESSAGE_SIZE];
                  int msgLen = sizeof(msg);

                  StunAddress4 from;

                  getMessage( myFd,
                              msg,
                              &msgLen,
                              &from.addr,
                              &from.port,verbose );

                  StunMessage resp;
                  memset(&resp, 0, sizeof(StunMessage));

                  stunParseMessage( msg,msgLen, &resp, verbose );

                  if ( verbose )
                  {
                     fprintf(stdout, "Received message of type %02x   id=%d\n", resp.msgHdr.msgType, (int)(resp.msgHdr.id.octet[0]));
                  }

                  if ( resp.msgHdr.id.octet[0] == 1)
                  {
                     if ( !respTestI )
                     {

                        testIchangedAddr.addr = resp.changedAddress.ipv4.addr;
                        testIchangedAddr.port = resp.changedAddress.ipv4.port;
                        testImappedAddr.addr = resp.mappedAddress.ipv4.addr;
                        testImappedAddr.port = resp.mappedAddress.ipv4.port;

                        respTestPreservePort = ( testImappedAddr.port == port );
                        if ( preservePort )
                        {
                           *preservePort = respTestPreservePort;
                        }

                        testI2dest.addr = resp.changedAddress.ipv4.addr;
                        count = 5;
                     }
                     respTestI=true;
                  }
               }
            }
         }
      }
   }

   // see if we can bind to this address
   //cerr << "try binding to " << testImappedAddr);
   //printf("WAN IP: %08x MAP IP:%08x\n", htonl(wAddr.addr), testImappedAddr.addr);
   if (respTestI == true)
      syslog(LOG_INFO, DVLOG_MARK_ADMIN "Binding-Response " H_RECEIVE H_SUCCESS);
   //syslog(LOG_WARNING, "Binding-Response " H_RECEIVE H_SUCCESS);

   if ( htonl(wAddr.addr) == testImappedAddr.addr || testImappedAddr.addr == 0)
   {
      isNat = false;
	  map_ip.s_addr = wAddr.addr;
	  TLOG_PRINT("STUN : IP Type - Public(%s/%hu)\n", inet_ntoa(map_ip), htons(testImappedAddr.port));
      //cerr << "binding worked");
   }
   else
   {
      isNat = true;
	  map_ip.s_addr = testImappedAddr.addr;
	  TLOG_PRINT("STUN : IP Type - Private(%s/%hu)\n", inet_ntoa(map_ip), htons(testImappedAddr.port));
   }
   *publicIp = htonl(testImappedAddr.addr);
   *mappedPort = htons(testImappedAddr.port);
   close(myFd1);
   close(myFd2);
   return isNat;

}


int
stunOpenSocket( StunAddress4 dest, StunAddress4* mapAddr,
                int port, StunAddress4* srcAddr,
                int verbose )
{
   struct in_addr in;
   if ( port == 0 )
   {
      port = stunRandomPort();
   }
   unsigned int interfaceIp = 0;
   if ( srcAddr )
   {
      interfaceIp = srcAddr->addr;
   }

   Socket myFd = openPort(port,interfaceIp,verbose);
   if (myFd == INVALID_SOCKET)
   {
      return myFd;
   }

   char msg[STUN_MAX_MESSAGE_SIZE];
   int msgLen = sizeof(msg);

   StunAtrString username;
   StunAtrString password;

   username.sizeValue = 0;
   password.sizeValue = 0;

#ifdef USE_TLS
   stunGetUserNameAndPassword( dest, username, password );
#endif

   stunSendTest(myFd, dest, username, password, 1, 0/*false*/ );

   StunAddress4 from;

   getMessage( myFd, msg, &msgLen, &from.addr, &from.port,verbose );

   StunMessage resp;
   memset(&resp, 0, sizeof(StunMessage));

   bool ok = stunParseMessage( msg, msgLen, &resp, verbose );
   if (!ok)
   {
      return -1;
   }

   StunAddress4 mappedAddr = resp.mappedAddress.ipv4;
   //StunAddress4 changedAddr = resp.changedAddress.ipv4;

   fprintf(stdout, "--- stunOpenSocket --- ");
   //fprintf(stdout, "\treq  id=" << req.id);
   //fprintf(stdout, "\tresp id=" << id);
   in.s_addr = mappedAddr.addr;
   fprintf(stdout, "\tmappedAddr=%s:%u\n", inet_ntoa(in), mappedAddr.port);

   *mapAddr = mappedAddr;

   return myFd;
}


int
stunOpenSocketPair( StunAddress4 dest, StunAddress4* mapAddr,
                    int* fd1, int* fd2,
                    int port, StunAddress4* srcAddr,
                    int verbose )
{
   const int NUM=3;

   if ( port == 0 )
   {
      port = stunRandomPort();
   }

   *fd1=-1;
   *fd2=-1;

   char msg[STUN_MAX_MESSAGE_SIZE];
   int msgLen =sizeof(msg);

   StunAddress4 from;
   int fd[NUM];
   int i;

   unsigned int interfaceIp = 0;
   if ( srcAddr )
   {
      interfaceIp = srcAddr->addr;
   }

   for( i=0; i<NUM; i++)
   {
      fd[i] = openPort( (port == 0) ? 0 : (port + i),
                        interfaceIp, verbose);
      if (fd[i] < 0)
      {
         while (i > 0)
         {
            close(fd[--i]);
         }
         return false;
      }
   }

   StunAtrString username;
   StunAtrString password;

   username.sizeValue = 0;
   password.sizeValue = 0;

#ifdef USE_TLS
   stunGetUserNameAndPassword( dest, username, password );
#endif

   for( i=0; i<NUM; i++)
   {
      stunSendTest(fd[i], dest, username, password, 1/*testNum*/, verbose );
   }

   StunAddress4 mappedAddr[NUM];
   for( i=0; i<NUM; i++)
   {
      msgLen = sizeof(msg)/sizeof(*msg);
      getMessage( fd[i],
                  msg,
                  &msgLen,
                  &from.addr,
                  &from.port ,verbose);

      StunMessage resp;
      memset(&resp, 0, sizeof(StunMessage));

      bool ok = stunParseMessage( msg, msgLen, &resp, verbose );
      if (!ok)
      {
         return false;
      }

      mappedAddr[i] = resp.mappedAddress.ipv4;
      //StunAddress4 changedAddr = resp.changedAddress.ipv4;
   }

   if (verbose)
   {
      fprintf(stdout, "--- stunOpenSocketPair --- ");
      for( i=0; i<NUM; i++)
      {
         fprintf(stdout, "\t mappedAddr=%08x", mappedAddr[i].addr);
      }
   }

   if ( mappedAddr[0].port %2 == 0 )
   {
      if (  mappedAddr[0].port+1 ==  mappedAddr[1].port )
      {
         *mapAddr = mappedAddr[0];
         *fd1 = fd[0];
         *fd2 = fd[1];
         close( fd[2] );
         return true;
      }
   }
   else
   {
      if (( mappedAddr[1].port %2 == 0 )
            && (  mappedAddr[1].port+1 ==  mappedAddr[2].port ))
      {
         *mapAddr = mappedAddr[1];
         *fd1 = fd[1];
         *fd2 = fd[2];
         close( fd[0] );
         return true;
      }
   }

   // something failed, close all and return error
   for( i=0; i<NUM; i++)
   {
      close( fd[i] );
   }

   return false;
}


static int getNatType(int *publicIp, unsigned short *mappedPort, int srcPort)
{
   int presPort=false;
   int hairpin=false;
   NatType stype;

   if ( stunServerAddr.addr == 0 )
      return -1;

   stype = stunNatType(stunServerAddr, 0, &presPort, &hairpin, srcPort, publicIp, mappedPort);
   //fprintf(stdout, "STUNType : %d, %s\n", stype, inet_ntoa(*(struct in_addr *)publicIp));

   return stype;

}


int send_stun_msg(int *fd, unsigned short new)
{
   StunMessage req;
   StunAtrString username;
   StunAtrString password;
   char buf[STUN_MAX_MESSAGE_SIZE];
   int len = STUN_MAX_MESSAGE_SIZE;
   int ret;
   int org=0;
   int	optLen = sizeof(int);

//	printf("%s:%d Stun Server IP: %08x, port=%d, fd=%d\n", __FUNCTION__, __LINE__, stunServerAddr.addr, stunServerAddr.port, *fd);
   if (*fd < 0)
      *fd = openPort(SrcPort, wAddr.addr, 0);

   memset(&req, 0, sizeof(StunMessage));

   username.sizeValue = 0;
   password.sizeValue = 0;

   stunBuildReqSimple( &req, username,
                       false , false , 0x0c );


   len = stunEncodeMessage(req, buf, len, password, 0);
   if (new != 0)
   {
      int  ip_ttl = (int)new;
      ret = getsockopt(*fd, IPPROTO_IP, IP_TTL, &org, (socklen_t *)&optLen);
      optLen = sizeof(ip_ttl);
      ret = setsockopt(*fd, IPPROTO_IP, IP_TTL, &ip_ttl, optLen);
   }

   if (org==0) org=64;

   ret = sendMessage(*fd, buf, len, stunServerAddr.addr, stunServerAddr.port, 0);

   if (new != 0)
   {
      ret = setsockopt(*fd, IPPROTO_IP, IP_TTL, &org, optLen);
   }

//	if (ret == 0)
//		fprintf(stdout, "Send Error: %s\n", strerror(errno));

   return ret;
}


int init_udp_process(int *publicIp, unsigned short *mappedPort, int *stunfd)
{
   int 			sockfd;
   char 			t[64], *ptr;
   char			serverAddr[32];
   int          	stun_port;
   int				debug=1;
   int				isNat =1;
   int ret = 0;
   struct in_addr addr;

   get_wanip(t, sizeof(t));
   wAddr.addr = inet_addr(t);
   wAddr.port = htons(SrcPort);

   addr.s_addr = 0;

   *publicIp =0;
   stun_port = atoi(nvram_safe_get_r("cwmp_hpms_port", t, sizeof(t)));
   if (stun_port ==0)
      stun_port = 3478;
   ptr = nvram_safe_get_r("cwmp_hpms_server", t, sizeof(t));
   if (*ptr == 0)
   {
      snprintf(t, sizeof(t), "%s", "stms.lgqps.com");
   }

   ret = dnsQuery(t, (unsigned int *)(&addr.s_addr));
   if (ret == 0)
   {
      snprintf(t, sizeof(t), "%s", inet_ntoa(addr));
      nvram_set("cwmp_hpms_ip", t);
   }
   else
   {
      int  mod;

      nvram_safe_get_r("cwmp_hpms_ipaddr", t, sizeof(t));
      if (t[0]==0)
         snprintf(t, sizeof(t), "%s", "180.225.21.216");
      nvram_set("cwmp_hpms_ip", t);
      mod = htonl(wAddr.addr) % 2;
      addr.s_addr = inet_addr(t) + htonl(mod);

   }

   if (inet_addr(t) == INADDR_NONE)
      return 0;

   snprintf(serverAddr, sizeof(serverAddr), "%s:%d", inet_ntoa(addr), stun_port);
   snprintf(t, sizeof(t), "%s", inet_ntoa(addr));

   stunParseServerName(serverAddr, &stunServerAddr);
   if ( stunServerAddr.addr == 0 )
      return 0;

   SrcPort = stunRandomPort();
   isNat = getNatType(publicIp, mappedPort, SrcPort);

//   SrcPort = atoi(nvram_safe_get_r("cwmp_cpe_server_port", t, sizeof(t)));
//   if (SrcPort ==0)
//      SrcPort = 8082;
   sockfd = openPort(SrcPort, 0, debug);
   if (sockfd < 0)
   {
      fprintf(stdout, "UDP Open Error...%d\n", errno);
      return 0;
   }
   *stunfd = sockfd;

   if (isNat)
   {
      notify_update("InternetGatewayDevice.ManagementServer.UDPConnectionRequestAddress",
                    CWMP_NTF_FORCED|CWMP_NTF_ACT, CWMP_ACS_MASK);
      return SrcPort;
   }

   return 0;
}

int handle_message(int *publicIp, unsigned short *mappedPort, char *buf, int recvLen)
{
   StunMessage resp;
   int ok;
   memset(&resp, 0, sizeof(StunMessage));

   ok = stunParseMessage( buf, recvLen, &resp, 1 );
   if (ok)
   {
      *publicIp = htonl(resp.mappedAddress.ipv4.addr);
      *mappedPort = htons(resp.mappedAddress.ipv4.port);
   }

   return ok;
}

