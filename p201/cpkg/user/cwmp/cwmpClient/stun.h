#ifndef STUN_H
#define STUN_H

#include <time.h>
#include <typedefs.h>

// if you change this version, change in makefile too 
#define STUN_VERSION "0.97"

#define STUN_MAX_STRING 256
#define STUN_MAX_UNKNOWN_ATTRIBUTES 8
#define STUN_MAX_MESSAGE_SIZE 2048

#define STUN_PORT 3478

typedef struct { unsigned char octet[16]; }  uint128;

/// define a structure to hold a stun address 
const uint8  IPv4Family = 0x01;
const uint8  IPv6Family = 0x02;

// define  flags  
const uint32 ChangeIpFlag   = 0x04;
const uint32 ChangePortFlag = 0x02;

// define  stun attribute
#define MappedAddress    0x0001
#define ResponseAddress  0x0002
#define ChangeRequest    0x0003
#define SourceAddress    0x0004
#define ChangedAddress   0x0005
#define Username         0x0006
#define Password         0x0007
#define MessageIntegrity 0x0008
#define ErrorCode        0x0009
#define UnknownAttribute 0x000A
#define ReflectedFrom    0x000B
#define XorMappedAddress 0x8020
#define XorOnly          0x0021
#define ServerName       0x8022
#define SecondaryAddress 0x8050 // Non standard extention

// define types for a stun message 
#define BindRequestMsg               0x0001
#define BindResponseMsg              0x0101
#define BindErrorResponseMsg         0x0111
#define SharedSecretRequestMsg       0x0002
#define SharedSecretResponseMsg      0x0102
#define SharedSecretErrorResponseMsg 0x0112

typedef struct 
{
      uint16 msgType;
      uint16 msgLength;
      uint128 id;
} StunMsgHdr;


typedef struct
{
      uint16 type;
      uint16 length;
} StunAtrHdr;

typedef struct
{
      uint16 port;
      uint32 addr;
} StunAddress4;

typedef struct
{
      uint8 pad;
      uint8 family;
      StunAddress4 ipv4;
} StunAtrAddress4;

typedef struct
{
      uint32 value;
} StunAtrChangeRequest;

typedef struct
{
      uint16 pad; // all 0
      uint8 errorClass;
      uint8 number;
      char reason[STUN_MAX_STRING];
      uint16 sizeReason;
} StunAtrError;

typedef struct
{
      uint16 attrType[STUN_MAX_UNKNOWN_ATTRIBUTES];
      uint16 numAttributes;
} StunAtrUnknown;

typedef struct
{
      char value[STUN_MAX_STRING];      
      uint16 sizeValue;
} StunAtrString;

typedef struct
{
      char hash[20];
} StunAtrIntegrity;

typedef enum 
{
   HmacUnkown=0,
   HmacOK,
   HmacBadUserName,
   HmacUnkownUserName,
   HmacFailed,
} StunHmacStatus;

typedef struct
{
      StunMsgHdr msgHdr;
	
      int hasMappedAddress;
      StunAtrAddress4  mappedAddress;
	
      int hasResponseAddress;
      StunAtrAddress4  responseAddress;
	
      int hasChangeRequest;
      StunAtrChangeRequest changeRequest;
	
      int hasSourceAddress;
      StunAtrAddress4 sourceAddress;
	
      int hasChangedAddress;
      StunAtrAddress4 changedAddress;
	
      int hasUsername;
      StunAtrString username;
	
      int hasPassword;
      StunAtrString password;
	
      int hasMessageIntegrity;
      StunAtrIntegrity messageIntegrity;
	
      int hasErrorCode;
      StunAtrError errorCode;
	
      int hasUnknownAttributes;
      StunAtrUnknown unknownAttributes;
	
      int hasReflectedFrom;
      StunAtrAddress4 reflectedFrom;

      int hasXorMappedAddress;
      StunAtrAddress4  xorMappedAddress;
	
      int xorOnly;

      int hasServerName;
      StunAtrString serverName;
      
      int hasSecondaryAddress;
      StunAtrAddress4 secondaryAddress;
} StunMessage; 


// Define enum with different types of NAT 
typedef enum 
{
   StunTypeUnknown=0,
   StunTypeFailure,
   StunTypeOpen,
   StunTypeBlocked,

   StunTypeIndependentFilter,
   StunTypeDependentFilter,
   StunTypePortDependedFilter,
   StunTypeDependentMapping,

   //StunTypeConeNat,
   //StunTypeRestrictedNat,
   //StunTypePortRestrictedNat,
   //StunTypeSymNat,
   
   StunTypeFirewall,
} NatType;

#ifdef WIN32
typedef SOCKET Socket;
#else
typedef int Socket;
#endif

#define MAX_MEDIA_RELAYS 500
#define MAX_RTP_MSG_SIZE 1500
#define MEDIA_RELAY_TIMEOUT 3*60

typedef struct 
{
      int relayPort;       // media relay port
      int fd;              // media relay file descriptor
      StunAddress4 destination; // NAT IP:port
      time_t expireTime;      // if no activity after time, close the socket 
} StunMediaRelay;

typedef struct
{
      StunAddress4 myAddr;
      StunAddress4 altAddr;
      Socket myFd;
      Socket altPortFd;
      Socket altIpFd;
      Socket altIpPortFd;
      int relay; // true if media relaying is to be done
      StunMediaRelay relays[MAX_MEDIA_RELAYS];
} StunServerInfo;

int
stunParseMessage( char* buf, 
                  unsigned int bufLen, 
                  StunMessage *message, 
                  int verbose );

void
stunBuildReqSimple( StunMessage* msg,
                    const StunAtrString username,
                    int changePort, int changeIp, unsigned int id);

unsigned int
stunEncodeMessage( const StunMessage message, 
                   char* buf, 
                   unsigned int bufLen, 
                   const StunAtrString password,
                   int verbose);

void
stunCreateUserName(const StunAddress4 addr, StunAtrString* username);

void 
stunGetUserNameAndPassword(  const StunAddress4 dest, 
                             StunAtrString* username,
                             StunAtrString* password);

void
stunCreatePassword(const StunAtrString username, StunAtrString* password);

int 
stunRand();

uint64
stunGetSystemTimeSecs();

/// find the IP address of a the specified stun server - return false is fails parse 
int  
stunParseServerName( char* serverName, StunAddress4 *stunServerAddr);

int 
stunParseHostName( char* peerName,
                   uint32 *ip,
                   uint16 *portVal,
                   uint16 defaultPort );

/// returns number of address found - take array or addres 
int 
stunFindLocalInterfaces(uint32* addresses, int maxSize );

void 
stunTest( StunAddress4 *dest, int testNum, int verbose, StunAddress4* srcAddr);

NatType
stunNatType( StunAddress4 dest, int verbose, 
             int* preservePort, // if set, is return for if NAT preservers ports or not
             int* hairpin ,  // if set, is the return for if NAT will hairpin packets
             int port, // port to use for the test, 0 to choose random port
             int *publicIp,
             unsigned short *mappedPort
   );


int
stunOpenSocket( StunAddress4 dest, 
                StunAddress4 *mappedAddr, 
                int port, 
                StunAddress4 *srcAddr, 
                int verbose );

int
stunOpenSocketPair( StunAddress4 dest, StunAddress4* mappedAddr, 
                    int* fd1, int* fd2, 
                    int srcPort,  StunAddress4* srcAddr,
                    int verbose);

int
stunRandomPort();

#endif


