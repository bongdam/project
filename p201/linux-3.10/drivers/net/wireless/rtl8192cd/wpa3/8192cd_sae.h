
#ifndef _SAE_H_
#define _SAE_H_

#include "../mesh_ext/mesh.h"

#include "./src_mbedtls/mbedtls/library/mbedtls/ecp.h"
#include "./src_mbedtls/mbedtls/library/mbedtls/bignum.h"
#include "./src_mbedtls/mbedtls/library/mbedtls/md.h"

#define SAE_TABLE_SIZE	5 /* the real size is power of 2*/

/*add for AUTH_SAE_STA*/
enum issue_auth_handle_result {
	ISSUE_AUTH_GO_ON_NORMAL,
	ISSUE_AUTH_FAIL,	/*alloc_stainfo fail */
	ISSUE_AUTH_GO_ON_SAE,
	ISSUE_AUTH_BLACKLIST	/*peer on blacklist */
};
enum result {
	NO_ERR,
	ERR_NOT_FATAL,
	ERR_FATAL,
	ERR_BLACKLIST
};
/*add for AUTH_SAE_STA*/

#define PRINT_SAE_EN 0		//eric-logo

#define SAE_AUTH_ALG                    3

#define SAE_AUTH_COMMIT                 1
#define SAE_AUTH_CONFIRM                2

#define  NUM_GROUPS 					5
#define  RETRANS 						3
#define  PMK_EXPIRE 					86400
#define  OPEN_THRESHOLD 				15
#define  BLACKLIST_TIMEOUT  			30
#define  GIVEUP_THRESHOLD 				5
#define  DESTORY_PEER 					5

#define WLAN_STATUS_SUCCESSFUL                  0
#define WLAN_STATUS_UNSPECIFIED_FAILURE         1
#define WLAN_STATUS_AUTHENTICATION_TIMEOUT      16
#define WLAN_STATUS_REQUEST_DECLINED            37
#define WLAN_STATUS_ANTI_CLOGGING_TOKEN_NEEDED  76
#define WLAN_STATUS_NOT_SUPPORTED_GROUP         77

#define IEEE802_11_IE_SSID                      0
#define IEEE802_11_HDR_LEN                      24

#define SAE_DEBUG_ERR           0x01
#define SAE_DEBUG_PROTOCOL_MSG  0x02
#define SAE_DEBUG_STATE_MACHINE 0x04
#define SAE_DEBUG_CRYPTO        0x08
#define SAE_DEBUG_CRYPTO_VERB   0x10
#define AMPE_DEBUG_CANDIDATES   0x20
#define MESHD_DEBUG             0x40
#define AMPE_DEBUG_FSM          0x80
#define AMPE_DEBUG_KEYS        0x100
#define AMPE_DEBUG_ERR         0x200
#define SAE_DEBUG_REKEY        0x400
#define SAE_DEBUG_MBED			0x800
#define IEEE802_11_FC_GET_TYPE(fc)  (((fc) & 0x000c) >> 2)
#define IEEE802_11_FC_GET_STYPE(fc) (((fc) & 0x00f0) >> 4)

#ifndef MAC2STR
#define MAC2STR(a) (a)[0]&0xff, (a)[1]&0xff, (a)[2]&0xff, (a)[3]&0xff, (a)[4]&0xff, (a)[5]&0xff
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

#define MBEDTLS_DIGEST_LENGTH	32

enum plink_state {
	PLINK_LISTEN,
	PLINK_OPN_SNT,
	PLINK_OPN_RCVD,
	PLINK_CNF_RCVD,
	PLINK_ESTAB,
	PLINK_HOLDING,
	PLINK_BLOCKED
};

enum sae_state {
	SAE_NOTHING,
	SAE_COMMITTED,
	SAE_CONFIRMED,
	SAE_ACCEPTED,
};

//#if defined(CONFIG_WLAN_HAL_8197F)
#ifdef _LITTLE_ENDIAN_
/*
 * IEEE does things backwards, networking in non-network order.
 */
#define ieee_order(x)   (x)	/* if LE, do nothing */
#else
static inline unsigned short ieee_order(unsigned short x)
{				/* if BE, byte-swap */
	return ((x & 0xff) << 8) | (x >> 8);
}
#endif

typedef struct group_def_ {
	unsigned short group_num;
	mbedtls_ecp_group *group;
	mbedtls_mpi *order;
	mbedtls_mpi *prime;
	unsigned char password[80];
	struct group_def_ *next;
} GD;

struct candidate {
	// TAILQ_ENTRY(candidate) entry;
	GD *grp_def;
	mbedtls_ecp_point *pwe;
	unsigned char pmkid[16];
	unsigned char pmk[MBEDTLS_DIGEST_LENGTH];
	unsigned char kck[MBEDTLS_DIGEST_LENGTH];
	mbedtls_mpi *private_val;
	mbedtls_mpi *peer_scalar;
	mbedtls_mpi *my_scalar;
	mbedtls_ecp_point *peer_element;
	mbedtls_ecp_point *my_element;
	unsigned long beacons;
	unsigned int failed_auth;
	unsigned long t0;
	unsigned long t1;
	unsigned long black_list_time;
	unsigned short state;
	unsigned short got_token;
	unsigned short sync;
	unsigned short sc;
	unsigned short rc;
	unsigned char peer_mac[ETH_ALEN];
	unsigned char my_mac[ETH_ALEN];
	/*  AMPE related fields */
	unsigned long t2;
	enum plink_state link_state;
	u16 my_lid;
	u16 peer_lid;		//le16
	unsigned char my_nonce[32];
	unsigned char peer_nonce[32];
	unsigned short reason;
	unsigned short retries;
	unsigned int timeout;
	unsigned char aek[MBEDTLS_DIGEST_LENGTH];
	unsigned char mtk[16];
	unsigned char mgtk[16];
	unsigned int mgtk_expiration;
	unsigned char igtk[16];
	u16 igtk_keyid;
	//unsigned char sup_rates[MAX_SUPP_RATES];
	unsigned short sup_rates_len;
	// siv_ctx sivctx;
	void *cookie;
	// struct ampe_config *conf;
	unsigned int ch_type;	/* nl80211_channel_type */
	int candidate_id;

	//timerid rekey_ping_timer;
	unsigned int rekey_ping_count;
	unsigned int rekey_reauth_count;
	unsigned int rekey_ok;
	unsigned int rekey_ok_ping_rx;
};

void delete_peer(struct rtl8192cd_priv *priv, unsigned char *peer_mac);
int process_mgmt_frame(struct rtl8192cd_priv *priv, struct ieee80211_mgmt_frame *frame, int len,
		       unsigned char *local_mac_addr, void *cookie);
void sae_read_config(int signal);
void sae_dump_db(int signal);
int prf(unsigned char *key, int keylen, unsigned char *label, int labellen,
	unsigned char *context, int contextlen, unsigned char *result, int resultbitlen);

#endif
