
#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/init.h>
#include <asm/uaccess.h>
#include <linux/unistd.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/delay.h>
#endif

#include "../8192cd_cfg.h"
#include "../8192cd.h"
#include "../8192cd_debug.h"
#include "../8192cd_headers.h"
#include "./8192cd_sae.h"

#include "./hash_table.h"

unsigned int sae_debug_mask = (SAE_DEBUG_ERR | SAE_DEBUG_PROTOCOL_MSG);
//char sae_buf[512];


unsigned char support_wpa3(struct rtl8192cd_priv *priv)
{
	if (priv->pshare->rf_ft_var.saeforce == 1)
		return WPA3_ONLY;
	else if (priv->pshare->rf_ft_var.saeforce == 2)
		return WPA3_WPA2_BOTH;

	if (priv->pmib->dot1180211AuthEntry.dot11EnablePSK & PSK_WPA3) {
		if (priv->pmib->dot1180211AuthEntry.dot11EnablePSK & PSK_WPA2)
			return WPA3_WPA2_BOTH;
		else
			return WPA3_ONLY;
	} else
		return WPA3_NOT_SUPPORT;
}

int peer_support_wpa3(struct rtl8192cd_priv *priv, unsigned int t_stamp)
{
	/*
	BIT11 means the following OUI has been checked
	SAE_SHA256_AKM_SUITE[] = {0x00, 0x0F, 0xAC, 0x08};
	=> peer support WPA3, and  SHA256 is required
	*/
	//log("t_stamp=0x[%x]",t_stamp);
	if (t_stamp & BIT11)
		return 1;
	else
		return 0;
}

unsigned char search_pmkid_cache(struct rtl8192cd_priv *priv, unsigned char *pmkid)
{
	unsigned idx = 0;

	for (idx = 0; idx < NUM_PMKID_CACHE; idx++) {
		if (!memcmp(&priv->wpa_global_info->pmkid_cache.pmkid[idx], pmkid, LEN_PMKID)) {
			log("found,idx=%d", idx);
			return idx;
		}
	}
	log("search by [%pm] no found", pmkid);
	return NUM_PMKID_CACHE;
}

/*add for AUTH_SAE_STA*/
unsigned char search_by_mac_pmkid_cache(struct rtl8192cd_priv *priv, unsigned char *peermac)
{
	unsigned char idx = 0;
	for (; idx < NUM_PMKID_CACHE; idx++) {
		if (memcmp(&priv->wpa_global_info->pmkid_cache.peermac[idx], peermac, 6) == 0) {
			return idx;
		}
	}
	log("search by [%pm] no found", peermac);
	return NUM_PMKID_CACHE;
}

unsigned char pmkid_cached(struct stat_info *pstat)
{
	if (pstat->pmkid_caching_idx < NUM_PMKID_CACHE)
		return 1;
	else
		return 0;
}

/*record pmkid & peer's mac*/
void add_pmkid_cache(struct rtl8192cd_priv *priv, unsigned char *pmkid, unsigned char *pmk, unsigned char *peermac)
{
	unsigned char idx = 0;
	int found = 0;
	struct pmkid_caching *pmkid_cache_ptr = &priv->wpa_global_info->pmkid_cache;

	/*check if same pmkid or mac addr existed ; if existed del it */
	for (idx = 0; idx < NUM_PMKID_CACHE; idx++) {
		if (memcmp(&pmkid_cache_ptr->pmkid[idx], pmkid, LEN_PMKID) == 0) {
			memset(&pmkid_cache_ptr->pmkid[idx], 0, LEN_PMKID);
			memset(&pmkid_cache_ptr->peermac[idx], 0, 6);
			memset(&pmkid_cache_ptr->pmk[idx], 0, LEN_PMK);
			log("has same [pmkid] idx[%d]", idx);
			found = 1;
			break;
		}
		if (memcmp(&pmkid_cache_ptr->peermac[idx], peermac, 6) == 0) {
			memset(&pmkid_cache_ptr->pmkid[idx], 0, LEN_PMKID);
			memset(&pmkid_cache_ptr->peermac[idx], 0, 6);
			memset(&pmkid_cache_ptr->pmk[idx], 0, LEN_PMK);
			log("has same [macaddr] idx[%d]", idx);
			found = 1;
			break;
		}
	}

	if (found) {
		log("replace old entry,idx[%d]", idx);
	} else {
		idx = pmkid_cache_ptr->pmkid_cache_idx;
		log("\n Add new one,idx[%d]", idx);
		pmkid_cache_ptr->pmkid_cache_idx = ((idx + 1) % NUM_PMKID_CACHE);
	}

	memcpy(&pmkid_cache_ptr->pmkid[idx], pmkid, LEN_PMKID);
	memcpy(&pmkid_cache_ptr->pmk[idx], pmk, LEN_PMK);
	memcpy(&pmkid_cache_ptr->peermac[idx], peermac, 6);

#if	0			//def WPA3_STA_DEBUG
	dump_hex("PMKID cache", pmkid_cache_ptr->pmkid[idx], 6);
	dump_hex("PMK cache", pmkid_cache_ptr->pmk[idx], 6);
#endif

}

/*add for AUTH_SAE_STA*/
void pmkid_cache_del(struct rtl8192cd_priv *priv, int idx)
{
	struct pmkid_caching *pmkid_cache_ptr = &priv->wpa_global_info->pmkid_cache;
	memset(&pmkid_cache_ptr->pmkid[idx], 0, LEN_PMKID);
	memset(&pmkid_cache_ptr->peermac[idx], 0, 6);
	memset(&pmkid_cache_ptr->pmk[idx], 0, LEN_PMK);
	log("\n\n del pmkid idx[%d]\n", idx);
}

/*add for AUTH_SAE_STA*/
int sae_chk_peer_pmkid_cache(struct rtl8192cd_priv *priv,
			     struct stat_info *pstat, unsigned char *ie_buf, unsigned short ie_len)
{
	int idx = NUM_PMKID_CACHE;
	int result = 0;
	if (ie_len)
		dump_hex("4-1 RSN", ie_buf, ie_len);

	/*at issue_auth_req,handle_sae_auth,
	   we has got pstat->pmkid_caching_idx by  search_by_mac_pmkid_cache */
	//pstat->pmkid_caching_idx = search_by_mac_pmkid_cache(priv, pstat->cmn_info.mac_addr);

	if (pstat && (pmkid_cached(pstat))) {
		idx = pstat->pmkid_caching_idx;
		if (ie_len < 22) {
			/*DUT has cache, peer has no cache, del it */
			pmkid_cache_del(priv, idx);
			pstat->pmkid_caching_idx = NUM_PMKID_CACHE;
			log("DUT has cache, peer has no cache,DUT del cached pmk");
			result = 1;
		} else {

			/*compare with my keep pmkid cache */
			if (!memcmp(&priv->wpa_global_info->pmkid_cache.pmkid[idx], ie_buf + 6, LEN_PMKID)) {
				log("found pmkid cache @ 4-1");
			} else {
				/*DUT has cache, peer has no cache, del it */
				pmkid_cache_del(priv, idx);
				pstat->pmkid_caching_idx = NUM_PMKID_CACHE;
				log("DUT has cache, peer has no cache @ 4-1, del it");
				result = 1;
			}
		}
	} else {
		log("DUT hasn't cache PMKID");
		if (pstat == NULL)
			log("CP1");
		if (!(pmkid_cached(pstat)))
			log("CP2");
	}
	/*0: OK ; 1:DUTSTA has cache, peer has no cache,
	   active send disassoc to speed up reconnection */
	return result;
}

void report_event_sae(struct rtl8192cd_priv *priv, void *p1, void *p2, unsigned char id)
{
	//log("id[%d]");
	switch (id) {
	case REPORT_SAE_CONFIRMED:
		{
			struct candidate *peer = (struct candidate *)p1;
			struct stat_info *pstat = get_stainfo(priv, peer->peer_mac);
			if (pstat) {
				log("save peer's PMK");
				memcpy(pstat->wpa_sta_info->PMK, peer->pmk, LEN_PMK);
				//memcpy(pstat->sae.PMK, peer->pmk, LEN_PMK);
				memcpy(pstat->sae_pmk, peer->pmk, LEN_PMK);
				add_pmkid_cache(priv, peer->pmkid, peer->pmk, peer->peer_mac);

				pstat->state |= WIFI_AUTH_SUCCESS;
			} else {
				log("NULL STA");
			}

			break;
		}
	case REPORT_PMKID_IN_WPA2IE:
		{
			struct stat_info *pstat = (struct stat_info *)p1;
			unsigned char *pmkid = (unsigned char *)p2;
			unsigned char pmkid_idx = search_pmkid_cache(priv, pmkid);
			if (pstat && (pmkid_idx < NUM_PMKID_CACHE)) {
				memcpy(pstat->wpa_sta_info->PMK, &priv->wpa_global_info->pmkid_cache.pmk[pmkid_idx],
				       LEN_PMK);
#ifdef WPA3_STA_DEBUG
				dump_hex("PMKID", pmkid, 6);
				dump_hex("PMK", pstat->wpa_sta_info->PMK, 6);
#endif
				log("peer included PMK");

			} else {
				log("NULL STA or pmkid_idx=%d\n", pmkid_idx);
			}

			break;
		}

	default:
		log("Unknown event id = %d \n", id);
	}

	return;
}

//#include "mbedtls/lk.h"
#include "./src_mbedtls/mbedtls/library/mbedtls/ecp.h"
#include "./src_mbedtls/mbedtls/library/mbedtls/bignum.h"
#include "./src_mbedtls/mbedtls/library/mbedtls/md.h"
#include "./src_mbedtls/mbedtls/library/mbedtls/platform.h"
#include "./src_mbedtls/mbedtls/library/mbedtls/ctr_drbg.h"

static const unsigned char entropy_source_pr[96] = {
	0xc1, 0x80, 0x81, 0xa6, 0x5d, 0x44, 0x02, 0x16,
	0x19, 0xb3, 0xf1, 0x80, 0xb1, 0xc9, 0x20, 0x02,
	0x6a, 0x54, 0x6f, 0x0c, 0x70, 0x81, 0x49, 0x8b,
	0x6e, 0xa6, 0x62, 0x52, 0x6d, 0x51, 0xb1, 0xcb,
	0x58, 0x3b, 0xfa, 0xd5, 0x37, 0x5f, 0xfb, 0xc9,
	0xff, 0x46, 0xd2, 0x19, 0xc7, 0x22, 0x3e, 0x95,
	0x45, 0x9d, 0x82, 0xe1, 0xe7, 0x22, 0x9f, 0x63,
	0x31, 0x69, 0xd2, 0x6b, 0x57, 0x47, 0x4f, 0xa3,
	0x37, 0xc9, 0x98, 0x1c, 0x0b, 0xfb, 0x91, 0x31,
	0x4d, 0x55, 0xb9, 0xe9, 0x1c, 0x5a, 0x5e, 0xe4,
	0x93, 0x92, 0xcf, 0xc5, 0x23, 0x12, 0xd5, 0x56,
	0x2c, 0x4a, 0x6e, 0xff, 0xdc, 0x10, 0xd0, 0x68
};

static const unsigned char nonce_pers_pr[16] = {
	0xd2, 0x54, 0xfc, 0xff, 0x02, 0x1e, 0x69, 0xd2,
	0x29, 0xc9, 0xcf, 0xad, 0x85, 0xfa, 0x48, 0x6c
};

#define COUNTER_INFINITY        65535
#define REAUTH_JITTER		30

#if 0				//for testing

unsigned char QR_COPY[] =
    { 0xa6, 0x2a, 0x8f, 0x61, 0xcc, 0x7c, 0xfc, 0x8f, 0x1d, 0x71, 0xea, 0x4b, 0xa3, 0xbe, 0xcb, 0x48, 0xd6, 0x49, 0x2e,
	0x6f, 0x16, 0xa7, 0x3a, 0xe9, 0xda, 0x62, 0x83, 0x95, 0xc9, 0x5d, 0xf7, 0x9a
};

unsigned char QNR_COPY[] =
    { 0x6b, 0xe0, 0xdc, 0x22, 0x60, 0x5d, 0x62, 0xd8, 0xb5, 0xa2, 0x6d, 0x3c, 0xa4, 0x6e, 0xca, 0x06, 0x27, 0x75, 0xc4,
	0x01, 0x5c, 0xbc, 0x84, 0x8d, 0x5c, 0xf4, 0x3e, 0xcc, 0xc0, 0xd7, 0x8d, 0x43
};

unsigned char TMP2_COPY[] =
    { 0x24, 0xbe, 0xe2, 0x1b, 0x0b, 0xed, 0xf4, 0xc4, 0xbb, 0xf0, 0x1f, 0xbc, 0x79, 0x87, 0x49, 0xe5, 0x29, 0xa4, 0xcd,
	0x57, 0xfc, 0xa0, 0x3c, 0xc9, 0x30, 0xe1, 0xf5, 0x70, 0x8f, 0x43, 0xad, 0x88
};

unsigned char TMP1_COPY[] =
    { 0xa6, 0x6c, 0x24, 0x00, 0x3c, 0xbc, 0x25, 0x16, 0x1b, 0x2d, 0xee, 0xf1, 0xe8, 0x38, 0xb2, 0x02, 0xa0, 0x1f, 0xa9,
	0x03, 0x50, 0x33, 0x11, 0x26, 0x05, 0x6c, 0xab, 0xff, 0xf9, 0x66, 0x7e, 0x2a
};

unsigned char PRIVATE_COPY[] =
    { 0x9e, 0xdd, 0xed, 0x4d, 0xdc, 0xc8, 0xe3, 0xf3, 0x41, 0x20, 0x32, 0x3b, 0x99, 0x97, 0xef, 0xf6, 0x19, 0x0e, 0x53,
	0x7a, 0x2f, 0x22, 0x2f, 0x98, 0x14, 0xf3, 0xcf, 0x45, 0xbd, 0x9b, 0xb4, 0x3e
};

unsigned char MASK_COPY[] =
    { 0xc1, 0xd6, 0xfd, 0x01, 0x31, 0x8d, 0xbc, 0x5d, 0x66, 0x9c, 0xc9, 0xe9, 0x68, 0x32, 0x93, 0xad, 0xba, 0xa8, 0xe7,
	0xf6, 0xab, 0xcc, 0x61, 0x0f, 0xec, 0xd0, 0xdd, 0x36, 0x52, 0x5f, 0x6b, 0x4e
};
unsigned char TOKEN_COPY[] = { 0x99, 0x85, 0x53, 0x32 };

unsigned char PEER_SCALAR_COPY[] =
    { 0xe1, 0x0f, 0x7f, 0x1c, 0x7f, 0x65, 0x21, 0x18, 0xf0, 0x53, 0x68, 0x88, 0xd3, 0x21, 0xab, 0xaf, 0x9f, 0x9e, 0xac,
	0xcb, 0xdf, 0xf9, 0xad, 0x6e, 0xd6, 0xfa, 0xe7, 0x63, 0x94, 0x71, 0xb7, 0xcb
};

unsigned char PEER_ELEMENT_X_COPY[] =
    { 0xd8, 0x6a, 0xdd, 0xf6, 0x62, 0x3c, 0x64, 0x26, 0x33, 0xfc, 0xdf, 0xf1, 0x23, 0x60, 0x88, 0x96, 0x2c, 0xe9, 0x30,
	0xd5, 0xf6, 0x22, 0x93, 0x3a, 0xcd, 0x1e, 0x67, 0x21, 0x99, 0xbf, 0xf8, 0xe0
};

unsigned char PEER_ELEMENT_Y_COPY[] =
    { 0xd0, 0x57, 0x07, 0x2b, 0xa9, 0xce, 0x91, 0x50, 0x1a, 0xc9, 0xe6, 0x19, 0x28, 0xa1, 0x06, 0xa4, 0x5d, 0x40, 0xb2,
	0xdf, 0x2b, 0x7c, 0xb2, 0x7c, 0x7c, 0x85, 0xc6, 0x59, 0x5e, 0x6c, 0x33, 0x3b
};

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

#endif

#define    SAE_MAX_EC_GROUPS    10
//#define    SAE_MAX_PASSWORD_LEN 80

//int num_groups = 5;
int group[SAE_MAX_EC_GROUPS] = { 19, 20, 21, 25, 26 };

//char pwd[SAE_MAX_PASSWORD_LEN] = "12345678";

#define state_to_string(x) (x) == SAE_NOTHING ? "NOTHING" : \
                           (x) == SAE_COMMITTED ? "COMMITTED" : \
                           (x) == SAE_CONFIRMED ? "CONFIRMED" : \
                           (x) == SAE_ACCEPTED ? "ACCEPTED" : \
                           "unknown"

#define seq_to_string(x) (x) == SAE_AUTH_COMMIT ? "COMMIT" : \
                         (x) == SAE_AUTH_CONFIRM ? "CONFIRM" : \
                         "unknown"

#define status_to_string(x) (x) == WLAN_STATUS_ANTI_CLOGGING_TOKEN_NEEDED ? "TOKEN NEEDED" : \
                            (x) == WLAN_STATUS_NOT_SUPPORTED_GROUP ? "REJECTION" : \
                            "unknown"

#define PATH_MAX 4096

/*
 * forward declarations
 */
//static void reauth(timerid id, void *data);
#if (PRINT_SAE_EN == 1)
#define sae_debug(level,msg, ...) do {\
	if(sae_debug_mask&level)\
		printk("[%s %d]: " msg "\n", __func__,__LINE__,##__VA_ARGS__);\
	} while(0)
#else
#define sae_debug(level,msg, ...) NOP
#endif

#define sae_debug2(level,msg, ...) do {printk(KERN_ERR "[%s %d]: " msg "\n", __func__,__LINE__,##__VA_ARGS__);} while(0)

static size_t test_offset;
static int ctr_drbg_self_test_entropy(void *data, unsigned char *buf, size_t len)
{
	const unsigned char *p = data;
	memcpy(buf, p + test_offset, len);
	test_offset += len;
	return (0);
}

static void dump_buffer(unsigned char *buf, int len)
{
	int i;
#if (PRINT_SAE_EN == 1)
	for (i = 0; i < len; i++) {
		if (i && (i % 4 == 0)) {
			printk(" ");
		}
		if (i && (i % 32 == 0)) {
			printk("\n");
		}
		printk("%02x", buf[i]);
	}
	printk("\n");
#endif
}

static void print_buffer(char *str, unsigned char *buf, int len)
{
#if (PRINT_SAE_EN == 1)
	dump_hex(str,buf, len);
#endif
}

void fin(struct rtl8192cd_priv *priv, unsigned short reason, unsigned char *peer_mac, unsigned char *buf, int len)
{

#ifndef SMP_SYNC
	unsigned long flags;
#endif
	if (!reason && len) {
		SAVE_INT_AND_CLI(flags);
		log("peer[%pm] reson[%d], key len[%d]", peer_mac, reason, len);
		panic_printk("[%s](SAE done with peer[%pm])\n", priv->dev->name,peer_mac);
		//dump_hex("PMK", buf, 16);
		// start_peer_link(peer, (unsigned char *) mesh.mymacaddr, cookie);
		RESTORE_INT(flags);

	} else if (reason) {
		SAVE_INT_AND_CLI(flags);
		log("	SAE failed , reason[%u]", reason);
		HASH_DELETE(GET_ROOT(priv)->sae_peer_table, peer_mac);
		RESTORE_INT(flags);
	}
}

static void pp_a_bignum(char *str, mbedtls_mpi * bn)
{
	unsigned char *buf;
	int len;

	len = mbedtls_mpi_size(bn);
	if ((buf = kmalloc(len, GFP_ATOMIC)) == NULL) {
		return;
	}
	mbedtls_mpi_write_binary(bn, buf, len);
	print_buffer(str, buf, len);
	kfree(buf);
}

static int tmp_is_odd(const mbedtls_mpi * a)
{
	return mbedtls_mpi_get_bit(a, 0);
}

int tmp_ecp_safe_invert_jac(const mbedtls_ecp_group * grp, mbedtls_ecp_point * Q, unsigned char inv)
{
	int ret = -1;
	unsigned char nonzero;
	mbedtls_mpi mQY;

	mbedtls_mpi_init(&mQY);

	/* Use the fact that -Q.Y mod P = P - Q.Y unless Q.Y == 0 */
	if (mbedtls_mpi_sub_mpi(&mQY, &grp->P, &Q->Y) != 0) {
		sae_debug(SAE_DEBUG_MBED, " mbedtls_mpi_sub_mpi failed \n");
		goto cleanup;
	}
	sae_debug(SAE_DEBUG_MBED, " mQY = P - Q->Y\n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("mQY", &mQY);
		pp_a_bignum("Q->Y", &Q->Y);
	}
	nonzero = mbedtls_mpi_cmp_int(&Q->Y, 0) != 0;
	if (mbedtls_mpi_safe_cond_assign(&Q->Y, &mQY, inv & nonzero) != 0) {
		sae_debug(SAE_DEBUG_MBED, " mbedtls_mpi_safe_cond_assign failed \n");
		goto cleanup;
	}
	sae_debug(SAE_DEBUG_MBED, " After invert \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("Q->Y", &Q->Y);
	}
	ret = 0;

cleanup:
	mbedtls_mpi_free(&mQY);
	return (ret);
}

//refer https://crypto.stackexchange.com/questions/20627/point-decompression-on-an-elliptic-curve
/* r = sqrt(x^3 + ax + b) = (x^3 + ax + b) ^ ((P + 1) / 4) (mod P)
Lagrange's theorem implies y^p=y
*/
int tmp_set_compressed_coordinates_GFp(mbedtls_mpi * p, mbedtls_ecp_point * point, mbedtls_mpi * x, mbedtls_mpi * z,
				       mbedtls_mpi * rnd)
{
	int ret = -1;
	mbedtls_mpi *tmp1 = NULL, *tmp2 = NULL, *tmp3 = NULL;

	tmp1 = kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (tmp1 == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't create bignum for candidate!\n");
		goto fail;
	}
	mbedtls_mpi_init(tmp1);

	tmp2 = kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (tmp2 == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't create bignum for candidate!\n");
		goto fail;
	}
	mbedtls_mpi_init(tmp2);

	tmp3 = kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (tmp3 == NULL) {
		sae_debug(SAE_DEBUG_ERR, "unable to malloc space for mbedtls_mpi buffer!\n");
		goto fail;
	}
	mbedtls_mpi_init(tmp3);

	//Calculate (p+1)/4
	mbedtls_mpi_lset(tmp1, 1);	//set tmp1 = 1
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		sae_debug(SAE_DEBUG_MBED, " tmp1 = 1 \n");
		pp_a_bignum("tmp1", tmp1);
	}

	mbedtls_mpi_add_mpi(tmp2, p, tmp1);	//tmp2=p+1
	sae_debug(SAE_DEBUG_MBED, " tmp2 = p + 1 \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("tmp2", tmp2);
	}

	mbedtls_mpi_lset(tmp1, 4);	//set tmp1 = 4
	sae_debug(SAE_DEBUG_MBED, " tmp1 = 4 \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("tmp1", tmp1);
	}

	mbedtls_mpi_div_mpi(tmp3, NULL, tmp2, tmp1);	//tmp3=(p+1)/4
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		sae_debug(SAE_DEBUG_MBED, " tmp3 = (p+1)/4 \n");
		pp_a_bignum("pm1d2", tmp3);
	}
	//y_ = z ^ ((p+1)/4)
	mbedtls_mpi_exp_mod(tmp1, z, tmp3, p, NULL);	//tmp1=x_candidte^tmp3 mod prime

	if (sae_debug_mask & SAE_DEBUG_MBED) {
		log(" y_ = z ^ ((p+1)/4) \n");
		pp_a_bignum("y_", tmp1);
	}

	if (tmp_is_odd(rnd) != tmp_is_odd(tmp1)) {
		//tmp2 = p-y_
		mbedtls_mpi_sub_mpi(tmp2, p, tmp1);

		if (sae_debug_mask & SAE_DEBUG_MBED) {
			sae_debug(SAE_DEBUG_MBED, " is odd: y = p-y_ \n");
			pp_a_bignum("y", tmp2);
		}
		mbedtls_mpi_copy(&point->Y, tmp2);
	} else {
		sae_debug(SAE_DEBUG_MBED, " not odd: y = y_ \n");
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			pp_a_bignum("y", tmp1);
		}
		mbedtls_mpi_copy(&point->Y, tmp1);
	}

	mbedtls_mpi_copy(&point->X, x);

	ret = 0;
fail:
	if (tmp1) {
		mbedtls_mpi_free(tmp1);
		kfree(tmp1);
	}
	if (tmp2) {
		mbedtls_mpi_free(tmp2);
		kfree(tmp2);
	}
	if (tmp3) {
		mbedtls_mpi_free(tmp3);
		kfree(tmp3);
	}

	return ret;
}

int
prf(unsigned char *key, int keylen, unsigned char *label, int labellen,
    unsigned char *context, int contextlen, unsigned char *result, int resultbitlen)
{
	mbedtls_md_context_t ctx;
	unsigned char digest[MBEDTLS_DIGEST_LENGTH];
	int resultlen, len = 0;
	unsigned int mdlen = MBEDTLS_DIGEST_LENGTH;
	unsigned char mask = 0xff;
	unsigned short reslength;
	unsigned short i = 0, i_le;

	reslength = ieee_order(resultbitlen);
	resultlen = (resultbitlen + 7) / 8;
	do {
		i++;
		mbedtls_md_init(&ctx);
		mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
		i_le = ieee_order(i);
		mbedtls_md_hmac_starts(&ctx, (unsigned char *)key, keylen);
		mbedtls_md_hmac_update(&ctx, (unsigned char *)&i_le, sizeof(i_le));
		mbedtls_md_hmac_update(&ctx, label, labellen);
		mbedtls_md_hmac_update(&ctx, context, contextlen);
		mbedtls_md_hmac_update(&ctx, (unsigned char *)&reslength, sizeof(unsigned short));
		mbedtls_md_hmac_finish(&ctx, digest);

		sae_debug(SAE_DEBUG_MBED, " HMAC_Final \n");
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			print_buffer("digest", digest, MBEDTLS_DIGEST_LENGTH);
		}
		if ((len + mdlen) > resultlen) {
			memcpy(result + len, digest, resultlen - len);
		} else {
			memcpy(result + len, digest, mdlen);
		}
		len += mdlen;
		sae_debug(SAE_DEBUG_MBED, "");
		sae_debug(SAE_DEBUG_MBED, "len:%d, mdlen:%d\n", len, mdlen);
		mbedtls_md_free(&ctx);
	}
	while (len < resultlen);
	/*
	 * we're expanding to a bit length, if this is not a
	 * multiple of 8 bits then mask off the excess.
	 */
	if (resultbitlen % 8) {
		mask <<= (8 - (resultbitlen % 8));
		result[resultlen - 1] &= mask;
	}
	sae_debug(SAE_DEBUG_MBED, "");
	sae_debug(SAE_DEBUG_MBED, "resultlen:%d\n", resultlen);

	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("result", result, resultlen);
	}
	return resultlen;
}

void remove_from_blacklist(struct rtl8192cd_priv *priv, unsigned char *peer_mac)
{
	struct candidate *peer = HASH_SEARCH(GET_ROOT(priv)->sae_blacklist_table, peer_mac);

	if (peer) {
		sae_debug(SAE_DEBUG_PROTOCOL_MSG, "removing %pm from blacklist\n", peer->peer_mac);
		HASH_DELETE(GET_ROOT(priv)->sae_blacklist_table, peer->peer_mac);
		return;
	}
}

static void blacklist_peer(struct rtl8192cd_priv *priv, struct candidate *peer)
{
	struct candidate *fubar = NULL;

	if ((fubar = (struct candidate *)kmalloc(sizeof(struct candidate), GFP_ATOMIC)) != NULL) {
		memcpy(fubar->peer_mac, peer->peer_mac, ETH_ALEN);
		fubar->black_list_time = jiffies;
		HASH_INSERT(GET_ROOT(priv)->sae_blacklist_table, fubar->peer_mac, fubar);
		kfree(fubar);
	}
}

/*
 * delete_peer()
 *      Clean up state, remove peer from database, and free up memory.
 */
void delete_peer(struct rtl8192cd_priv *priv, unsigned char *peer_mac)
{
	struct candidate *peer = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, peer_mac);

	if (peer) {
		sae_debug(SAE_DEBUG_PROTOCOL_MSG, "deleting peer at %pm in state %s\n",
			  peer->peer_mac, state_to_string(peer->state));
		if ((peer->state == SAE_COMMITTED) || (peer->state == SAE_CONFIRMED)) {
			priv->curr_open--;
			if (priv->curr_open < 0) {
				/*
				 * one of those "should not happen" kinds of things
				 */
				sae_debug(SAE_DEBUG_ERR, "***ERROR*** we have %d currently open sessions\n",
					  priv->curr_open);
			}
		}
		// srv_rem_timeout(srvctx, peer->t0);     /* no harm if not set */
		peer->t0 = 0;
		//   srv_rem_timeout(srvctx, peer->t1);     /*      ditto         */
		peer->t1 = 0;
		//   srv_rem_timeout(srvctx, peer->t2);     /*      ditto         */
		peer->t2 = 0;
		//    srv_rem_timeout(srvctx, peer->rekey_ping_timer);
		// peer->rekey_ping_timer = 0;
		peer->black_list_time = 0;
		/*
		 * PWE, the private value, the PMK and KCK are all secret so
		 * take some special care when deleting them.
		 */

		memset(peer->pmk, 0, MBEDTLS_DIGEST_LENGTH);
		memset(peer->kck, 0, MBEDTLS_DIGEST_LENGTH);
		if (peer->peer_scalar) {
			mbedtls_mpi_free(peer->peer_scalar);
			kfree(peer->peer_scalar);
			peer->peer_scalar = NULL;
		}
		if (peer->peer_element) {
			mbedtls_ecp_point_free(peer->peer_element);
			kfree(peer->peer_element);
			peer->peer_element = NULL;
		}
		if (peer->my_scalar) {
			mbedtls_mpi_free(peer->my_scalar);
			kfree(peer->my_scalar);
			peer->my_scalar = NULL;
		}
		if (peer->my_element) {
			mbedtls_ecp_point_free(peer->my_element);
			kfree(peer->my_element);
			peer->my_element = NULL;
		}
		HASH_DELETE(GET_ROOT(priv)->sae_peer_table, peer_mac);

		return;
	}
	sae_debug(SAE_DEBUG_ERR, "peer no existed\n");
}

/*
 * a callback-able version of delete peer
 */
static void destroy_peer(struct rtl8192cd_priv *priv, int id, unsigned char *peer_mac)
{
	delete_peer(priv, peer_mac);
}

int on_blacklist(struct rtl8192cd_priv *priv, unsigned char *mac)
{
	struct candidate *peer = HASH_SEARCH(GET_ROOT(priv)->sae_blacklist_table, mac);
	if (peer) {
		return 1;
	} else
		return 0;
}

struct candidate *find_peer(struct rtl8192cd_priv *priv, unsigned char *mac, int accept)
{
	struct candidate *peer = NULL, *found = NULL;

	peer = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, mac);
	if (peer) {
		/*
		 * if "accept" then we're only looking for peers in "accepted" state
		 */
		if (accept) {
			if (peer->state == SAE_ACCEPTED) {
				return peer;
			}
			// continue;
			/*
			 * otherwise we'll take any peer but, if there are 2, give preference
			 * to the one not in "accepted" state
			 */
			if (found == NULL) {
				found = peer;
			} else {
				if ((found->state == SAE_ACCEPTED) && (peer->state != SAE_ACCEPTED)) {
					found = peer;
				}
			}
		}
	}
	return found;
}

#ifdef AUTH_SAE_STA
/*only looking for peers in "accepted" state*/
struct candidate *find_peer2(struct rtl8192cd_priv *priv, unsigned char *mac)
{
	struct candidate *peer = NULL, *found = NULL;
	peer = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, mac);
	if (peer) {
		if (peer->state == SAE_ACCEPTED) {
			log("found accepted peer[%pm]", mac);
			return peer;
		}
	}
	return found;
}

#endif
static int check_dup(struct rtl8192cd_priv *priv, int check_me, struct ieee80211_mgmt_frame *frame, int len)
{
	unsigned char *ptr = NULL;
	int itemsize, ret;
	mbedtls_mpi *scalar = NULL;

	struct candidate *peer = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, frame->sa);

	//if ((scalar = BN_new()) == NULL) {
	/*
	 * this seems kind of serious so return that it is a dupe so we don't
	 * do anymore processing of this frame
	 */
	//return 0;
	//}

	//log("check dump_hex for %pm", frame->sa);
	if (peer == NULL)
		return -1;
	scalar = kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (scalar == NULL) {
		return 0;
	}
	mbedtls_mpi_init(scalar);
	//ptr = (unsigned char *)(frame) + WLAN_HDR_A3_LEN + _AUTH_IE_OFFSET_ + sizeof(unsigned short);

	ptr = frame->authenticate.u.var8 + sizeof(unsigned short);
	if (peer->got_token) {
		/*
		 * we know how big the token is because we generated it in the first place!
		 */
		ptr += MBEDTLS_DIGEST_LENGTH;
	}
	itemsize = mbedtls_mpi_size(peer->grp_def->order);

	mbedtls_mpi_read_binary(scalar, ptr, itemsize);
	sae_debug(SAE_DEBUG_MBED, " write scalar \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("scalar", scalar);
	}
	sae_debug(SAE_DEBUG_MBED, "check_me: %d\n", check_me);
	if (check_me) {
		ret = mbedtls_mpi_cmp_mpi(peer->my_scalar, scalar);

#ifdef WPA3_STA_DEBUG
		if (ret == 0) {
			log("Ret=[%d] peer's scalar same with me", ret);
			pp_a_bignum("peer->my_scalar", peer->my_scalar);
			pp_a_bignum("peer->peer_scalar", scalar);
		}
#endif
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			pp_a_bignum("peer->my_scalar", peer->my_scalar);
			pp_a_bignum("peer->peer_scalar", scalar);
		}
	} else {
		ret = mbedtls_mpi_cmp_mpi(peer->peer_scalar, scalar);

		if (sae_debug_mask & SAE_DEBUG_MBED) {
			pp_a_bignum("peer->peer_scalar", peer->peer_scalar);
		}
	}
	mbedtls_mpi_free(scalar);
	kfree(scalar);
	scalar = NULL;
	return ret;
}

static int check_confirm(struct candidate *peer, struct ieee80211_mgmt_frame *frame)
{
	unsigned short sent_confirm;

	sent_confirm = ieee_order(*(frame->authenticate.u.var16));
	if ((sent_confirm > peer->rc) && (sent_confirm != COUNTER_INFINITY)) {
		return 1;
	} else {
		return 0;
	}
}

static int process_confirm(struct candidate *peer, struct ieee80211_mgmt_frame *frame, int len)
{
	unsigned char tmp[256];
	enum result r = NO_ERR;
	mbedtls_mpi *x = NULL;
	mbedtls_mpi *y = NULL;
	mbedtls_ecp_point *psum = NULL;
	mbedtls_md_context_t ctx;
	int offset;

	if (len != (IEEE802_11_HDR_LEN + sizeof(frame->authenticate) + sizeof(unsigned short) + MBEDTLS_DIGEST_LENGTH)) {
		sae_debug(SAE_DEBUG_ERR, "bad size of confirm message (%d)\n", len);
		r = ERR_NOT_FATAL;
		goto out;
	}

	psum = kmalloc(sizeof(mbedtls_ecp_point), GFP_ATOMIC);
	if (psum == NULL) {
		log("unable to construct confirm!\n");
		r = ERR_FATAL;
		goto out;

	}
	mbedtls_ecp_point_init(psum);

	mbedtls_md_init(&ctx);
	mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_md_hmac_starts(&ctx, peer->kck, MBEDTLS_DIGEST_LENGTH);	//need to verify

	peer->rc = ieee_order(*(frame->authenticate.u.var16));
	sae_debug(SAE_DEBUG_PROTOCOL_MSG, "processing confirm (%d)\n", peer->rc);
	/*
	 * compute the confirm verifier using the over-the-air format of send_conf
	 */
	mbedtls_md_hmac_update(&ctx, frame->authenticate.u.var8, sizeof(unsigned short));

	/* peer's scalar */
	offset = mbedtls_mpi_size(peer->grp_def->order) - mbedtls_mpi_size(peer->peer_scalar);
	memset(tmp, 0, offset);
	sae_debug(SAE_DEBUG_MBED, " Write peer scalar to tmp offset: %d, total: %d \n", offset,
		  mbedtls_mpi_size(peer->grp_def->order));

	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("peer->peer_scalar", peer->peer_scalar);
	}
	mbedtls_mpi_write_binary(peer->peer_scalar, tmp + offset, mbedtls_mpi_size(peer->peer_scalar));
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("tmp", tmp, mbedtls_mpi_size(peer->grp_def->order));
	}

	mbedtls_md_hmac_update(&ctx, tmp, mbedtls_mpi_size(peer->grp_def->order));

	x = &peer->peer_element->X;
	y = &peer->peer_element->Y;
	sae_debug(SAE_DEBUG_MBED, " coordinates of peer elements \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("x", x);
		pp_a_bignum("y", y);
	}

	/* Rarely x can be way too big, e.g. 1348 bytes. Corrupted packet? */
	if (mbedtls_mpi_size(peer->grp_def->prime) < mbedtls_mpi_size(x)
	    || mbedtls_mpi_size(peer->grp_def->prime) < mbedtls_mpi_size(y)) {
		sae_debug(SAE_DEBUG_ERR, "coords are too big, x = %d bytes, y = %d bytes\n", mbedtls_mpi_size(x),
			  mbedtls_mpi_size(y));
		r = ERR_NOT_FATAL;
		goto out;
	}

	/* peer's element */
	offset = mbedtls_mpi_size(peer->grp_def->prime) - mbedtls_mpi_size(x);
	memset(tmp, 0, offset);
	mbedtls_mpi_write_binary(x, tmp + offset, mbedtls_mpi_size(x));
	sae_debug(SAE_DEBUG_MBED, " Write peer_element x to tmp \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("tmp", tmp, mbedtls_mpi_size(peer->grp_def->prime));
	}

	mbedtls_md_hmac_update(&ctx, tmp, mbedtls_mpi_size(peer->grp_def->prime));

	offset = mbedtls_mpi_size(peer->grp_def->prime) - mbedtls_mpi_size(y);
	memset(tmp, 0, offset);
	mbedtls_mpi_write_binary(y, tmp + offset, mbedtls_mpi_size(y));
	sae_debug(SAE_DEBUG_MBED, " Write peer_element y to tmp \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("tmp", tmp, mbedtls_mpi_size(peer->grp_def->prime));
	}

	mbedtls_md_hmac_update(&ctx, tmp, mbedtls_mpi_size(peer->grp_def->prime));

	/* my scalar */
	offset = mbedtls_mpi_size(peer->grp_def->order) - mbedtls_mpi_size(peer->my_scalar);
	memset(tmp, 0, offset);
	mbedtls_mpi_write_binary(peer->my_scalar, tmp + offset, mbedtls_mpi_size(peer->my_scalar));
	sae_debug(SAE_DEBUG_MBED, " Write peer->my_scalar to tmp \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("tmp", tmp, mbedtls_mpi_size(peer->grp_def->order));
	}

	mbedtls_md_hmac_update(&ctx, tmp, mbedtls_mpi_size(peer->grp_def->order));

	x = &peer->my_element->X;
	y = &peer->my_element->Y;

	if (sae_debug_mask & SAE_DEBUG_MBED) {
		log("coordinates of my_element \n");
		pp_a_bignum("x", x);
		pp_a_bignum("y", y);
	}
	/* my element */
	offset = mbedtls_mpi_size(peer->grp_def->prime) - mbedtls_mpi_size(x);
	memset(tmp, 0, offset);
	mbedtls_mpi_write_binary(x, tmp + offset, mbedtls_mpi_size(x));

	if (sae_debug_mask & SAE_DEBUG_MBED) {
		log(" Write my_element x to tmp \n");
		print_buffer("tmp", tmp, mbedtls_mpi_size(peer->grp_def->prime));
	}

	mbedtls_md_hmac_update(&ctx, tmp, mbedtls_mpi_size(peer->grp_def->prime));

	offset = mbedtls_mpi_size(peer->grp_def->prime) - mbedtls_mpi_size(y);
	memset(tmp, 0, offset);
	mbedtls_mpi_write_binary(y, tmp + offset, (mbedtls_mpi_size(y)));
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		log(" Write my_element y to tmp \n");
		print_buffer("tmp", tmp, mbedtls_mpi_size(peer->grp_def->prime));
	}

	mbedtls_md_hmac_update(&ctx, tmp, mbedtls_mpi_size(peer->grp_def->prime));
	mbedtls_md_hmac_finish(&ctx, tmp);

	if (sae_debug_mask & SAE_DEBUG_MBED) {
		log(" hmac result \n");
		print_buffer("tmp", tmp, 128);
	}
	mbedtls_md_free(&ctx);

	if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
		print_buffer("peer's confirm",
			     frame->authenticate.u.var8, MBEDTLS_DIGEST_LENGTH + sizeof(unsigned short));
	}

	if (memcmp(tmp, (frame->authenticate.u.var8 + sizeof(unsigned short)), MBEDTLS_DIGEST_LENGTH)) {
		log("confirm did not verify!\n");
		r = ERR_BLACKLIST;
		goto out;
	}

	r = NO_ERR;

out:
	if (psum) {
		mbedtls_ecp_point_free(psum);
		kfree(psum);
		psum = NULL;
	}

	return r;
}

static int confirm_to_peer(struct rtl8192cd_priv *priv, u8 * sa)
{
	char buf[2048];
	unsigned char tmp[128];
	struct ieee80211_mgmt_frame *frame;
	size_t len = 0;
	mbedtls_mpi *x = NULL, *y = NULL;
	mbedtls_md_context_t ctx;
	unsigned short send_conf;
	int offset;
	struct candidate *peer = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, sa);

	if (peer == NULL)
		return;

	memset(buf, 0, sizeof(buf));
	frame = (struct ieee80211_mgmt_frame *)buf;
	frame->frame_control = ieee_order((IEEE802_11_FC_TYPE_MGMT << 2 | IEEE802_11_FC_STYPE_AUTH << 4));
	memcpy(frame->sa, peer->my_mac, ETH_ALEN);
	memcpy(frame->da, peer->peer_mac, ETH_ALEN);

	if (OPMODE & WIFI_AP_STATE)	//rtk_sae
		memcpy(frame->bssid, peer->my_mac, ETH_ALEN);
	else
		memcpy(frame->bssid, peer->peer_mac, ETH_ALEN);

	frame->authenticate.alg = ieee_order(SAE_AUTH_ALG);
	frame->authenticate.auth_seq = ieee_order(SAE_AUTH_CONFIRM);
	len = IEEE802_11_HDR_LEN + sizeof(frame->authenticate);

	if (peer->sc != COUNTER_INFINITY) {
		peer->sc++;
	}
	send_conf = ieee_order(peer->sc);
	//printk("sc is %d size is %d", send_conf, sizeof(frame->authenticate));
	memcpy(frame->authenticate.u.var8, (unsigned char *)&send_conf, sizeof(unsigned short));
	len += sizeof(unsigned short);

	mbedtls_md_init(&ctx);
	mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_md_hmac_starts(&ctx, peer->kck, MBEDTLS_DIGEST_LENGTH);	//need to verify

	/* send_conf is in over-the-air format now */
	mbedtls_md_hmac_update(&ctx, (unsigned char *)&send_conf, sizeof(unsigned short));

	/* my scalar */
	offset = mbedtls_mpi_size(peer->grp_def->order) - mbedtls_mpi_size(peer->my_scalar);
	memset(tmp, 0, offset);
	sae_debug(SAE_DEBUG_MBED, " Write my_scalar to tmp to hmac with offset: %d, total: %d\n", offset,
		  mbedtls_mpi_size(peer->grp_def->order));
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("peer->my_scalar", peer->my_scalar);
	}
	mbedtls_mpi_write_binary(peer->my_scalar, tmp + offset, mbedtls_mpi_size(peer->my_scalar));
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("tmp", tmp, mbedtls_mpi_size(peer->grp_def->order));
	}
	mbedtls_md_hmac_update(&ctx, tmp, mbedtls_mpi_size(peer->grp_def->order));

	x = &peer->my_element->X;
	y = &peer->my_element->Y;
	sae_debug(SAE_DEBUG_MBED, " coordinates of my_element \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("x", x);
		pp_a_bignum("y", y);
	}

	/* my element */
	offset = mbedtls_mpi_size(peer->grp_def->prime) - mbedtls_mpi_size(x);
	memset(tmp, 0, offset);
	mbedtls_mpi_write_binary(x, tmp + offset, mbedtls_mpi_size(x));
	sae_debug(SAE_DEBUG_MBED, " Write my_element x to tmp to hmac with offset: %d, total: %d\n", offset,
		  mbedtls_mpi_size(peer->grp_def->prime));
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("tmp", tmp, mbedtls_mpi_size(peer->grp_def->prime));
	}

	mbedtls_md_hmac_update(&ctx, tmp, mbedtls_mpi_size(peer->grp_def->prime));
	offset = mbedtls_mpi_size(peer->grp_def->prime) - mbedtls_mpi_size(y);
	memset(tmp, 0, offset);
	mbedtls_mpi_write_binary(y, tmp + offset, mbedtls_mpi_size(y));
	sae_debug(SAE_DEBUG_MBED, " Write my_element y to tmp to hmac with offset: %d, total: %d\n", offset,
		  mbedtls_mpi_size(peer->grp_def->prime));
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("tmp", tmp, mbedtls_mpi_size(peer->grp_def->prime));
	}

	mbedtls_md_hmac_update(&ctx, tmp, mbedtls_mpi_size(peer->grp_def->prime));

	/* peer's scalar */
	offset = mbedtls_mpi_size(peer->grp_def->order) - mbedtls_mpi_size(peer->peer_scalar);
	memset(tmp, 0, offset);
	sae_debug(SAE_DEBUG_MBED, " Write peer_scalar to tmp to hmac with offset: %d, total: %d\n", offset,
		  mbedtls_mpi_size(peer->grp_def->order));
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("peer->peer_scalar", peer->peer_scalar);
	}
	mbedtls_mpi_write_binary(peer->peer_scalar, tmp + offset, mbedtls_mpi_size(peer->peer_scalar));
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("tmp", tmp, mbedtls_mpi_size(peer->grp_def->order));
	}

	mbedtls_md_hmac_update(&ctx, tmp, mbedtls_mpi_size(peer->grp_def->order));

	x = &peer->peer_element->X;
	y = &peer->peer_element->Y;
	sae_debug(SAE_DEBUG_MBED, " coordinates of peer_element \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("x", x);
		pp_a_bignum("y", y);
	}
	/* peer's element */
	offset = mbedtls_mpi_size(peer->grp_def->prime) - mbedtls_mpi_size(x);
	memset(tmp, 0, offset);
	mbedtls_mpi_write_binary(x, tmp + offset, mbedtls_mpi_size(x));
	sae_debug(SAE_DEBUG_MBED, " Write peer_element x to tmp to hmac with offset: %d, total: %d\n", offset,
		  mbedtls_mpi_size(peer->grp_def->prime));
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("tmp", tmp, mbedtls_mpi_size(peer->grp_def->prime));
	}

	mbedtls_md_hmac_update(&ctx, tmp, mbedtls_mpi_size(peer->grp_def->prime));
	offset = mbedtls_mpi_size(peer->grp_def->prime) - mbedtls_mpi_size(y);
	memset(tmp, 0, offset);
	mbedtls_mpi_write_binary(y, tmp + offset, mbedtls_mpi_size(y));

	if (sae_debug_mask & SAE_DEBUG_MBED) {
		sae_debug(SAE_DEBUG_MBED, " Write peer_element y to tmp to hmac with offset: %d, total: %d\n",
			offset,mbedtls_mpi_size(peer->grp_def->prime));
		print_buffer("tmp", tmp, mbedtls_mpi_size(peer->grp_def->prime));
	}

	mbedtls_md_hmac_update(&ctx, tmp, mbedtls_mpi_size(peer->grp_def->prime));
	mbedtls_md_hmac_finish(&ctx, (frame->authenticate.u.var8 + sizeof(unsigned short)));

	if (sae_debug_mask & SAE_DEBUG_MBED) {
		sae_debug(SAE_DEBUG_MBED, " hmac result \n");
		print_buffer("tmp", (frame->authenticate.u.var8 + sizeof(unsigned short)), MBEDTLS_DIGEST_LENGTH);
	}
	mbedtls_md_free(&ctx);

	if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
		print_buffer("local confirm",
			     frame->authenticate.u.var8, MBEDTLS_DIGEST_LENGTH + sizeof(unsigned short));
	}

	len += MBEDTLS_DIGEST_LENGTH;

	/*INTEL SAE timing,we need this printk ; for IOT we must printk this line*/
	log2("sending confirm seq[%s] to peer[%pm] in[%s]",
		seq_to_string(ieee_order(frame->authenticate.auth_seq)),peer->peer_mac, state_to_string(peer->state));

	if (issue_sae_frame(priv, (u8 *) frame, len) != 0) {
		sae_debug(SAE_DEBUG_ERR, "can't send an authentication frame to %pm\n", peer->peer_mac);
		return -1;
	}
	return 0;
}

static int process_commit(struct rtl8192cd_priv *priv, struct ieee80211_mgmt_frame *frame, int len)
{
	mbedtls_mpi *x = NULL, *y = NULL, *k = NULL, *nsum = NULL, *tmp1 = NULL;
	int offset, itemsize, ret = 0;
	mbedtls_ecp_point *K = NULL;
	unsigned char *ptr = NULL, *tmp = NULL, keyseed[MBEDTLS_DIGEST_LENGTH], kckpmk[(MBEDTLS_DIGEST_LENGTH * 2) * 8];
	mbedtls_md_context_t ctx;
	struct candidate *peer = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, frame->sa);

	//log("");

	if (peer == NULL)
		return -1;

	/*
	 * check whether the frame is big enough (might be proprietary IEs or cruft appended)
	 */
	//dump_hex("commit received", frame, len);
	if (len < (IEEE802_11_HDR_LEN + sizeof(frame->authenticate) +
		   (2 * mbedtls_mpi_size(peer->grp_def->prime)) + mbedtls_mpi_size(peer->grp_def->order))) {
		sae_debug(SAE_DEBUG_ERR, "invalid size for commit message (%d < %d+%d+(2*%d)+%d = %d))\n", len,
			  IEEE802_11_HDR_LEN, sizeof(frame->authenticate), mbedtls_mpi_size(peer->grp_def->prime),
			  mbedtls_mpi_size(peer->grp_def->order),
			  (IEEE802_11_HDR_LEN + sizeof(frame->authenticate) +
			   (2 * mbedtls_mpi_size(peer->grp_def->prime)) + mbedtls_mpi_size(peer->grp_def->order)));
		return -1;
	}

	x = kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (x == NULL) {
		sae_debug(SAE_DEBUG_ERR, "unable to create x,y bignums\n");
		goto process_commit_fail;
	}
	mbedtls_mpi_init(x);

	y = kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (y == NULL) {
		sae_debug(SAE_DEBUG_ERR, "unable to create x,y bignums\n");
		goto process_commit_fail;
	}
	mbedtls_mpi_init(y);

	K = kmalloc(sizeof(mbedtls_ecp_point), GFP_ATOMIC);
	if (K == NULL) {
		sae_debug(SAE_DEBUG_ERR, "unable to create mbedtls_ecp_point\n");
		goto process_commit_fail;
	}
	mbedtls_ecp_point_init(K);

	ptr = frame->authenticate.u.var8;

	//ptr = (unsigned char *)(frame) + WLAN_HDR_A3_LEN + _AUTH_IE_OFFSET_;
	///ptr = frame + WLAN_HDR_A3_LEN + _AUTH_IE_OFFSET_;
	/*
	 * first thing in a commit is the finite cyclic group, skip the group
	 */
	ptr += sizeof(unsigned short);

	if (peer->got_token) {
		/*
		 * if we got a token then skip over it. We know the size because we
		 * created it in the first place!
		 */
		ptr += MBEDTLS_DIGEST_LENGTH;
	}

	/*
	 * first get the peer's scalar
	 */
	itemsize = mbedtls_mpi_size(peer->grp_def->order);
	mbedtls_mpi_read_binary(peer->peer_scalar, ptr, itemsize);
	//mbedtls_mpi_read_binary(peer->peer_scalar, PEER_SCALAR_COPY, itemsize);
	sae_debug(SAE_DEBUG_MBED, " get peer's scalar \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("peer->peer_scalar", peer->peer_scalar);
	}
	ptr += itemsize;
	/*
	 * then get x and y and turn them into the peer's element
	 */
	itemsize = mbedtls_mpi_size(peer->grp_def->prime);
	mbedtls_mpi_read_binary(x, ptr, itemsize);
	//mbedtls_mpi_read_binary(x, PEER_ELEMENT_X_COPY, itemsize);
	sae_debug(SAE_DEBUG_MBED, " get peer's element \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("x", x);
	}
	ptr += itemsize;

	mbedtls_mpi_read_binary(y, ptr, itemsize);
	//mbedtls_mpi_read_binary(y, PEER_ELEMENT_Y_COPY, itemsize);
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("y", y);
	}

	mbedtls_mpi_copy(&peer->peer_element->X, x);
	mbedtls_mpi_copy(&peer->peer_element->Y, y);
	mbedtls_mpi_lset(&peer->peer_element->Z, 1);
	sae_debug(SAE_DEBUG_MBED, " set peer_element");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("&peer->peer_element->X", &peer->peer_element->X);
		pp_a_bignum("&peer->peer_element->Y", &peer->peer_element->Y);
		pp_a_bignum("&peer->peer_element->Z", &peer->peer_element->Z);
	}
	sae_debug(SAE_DEBUG_MBED, " set peer_element");

	/*
	 * validate the scalar...
	 */
	tmp1 = kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (tmp1 == NULL) {
		sae_debug(SAE_DEBUG_ERR, "unable to create x,y bignums\n");
		goto process_commit_fail;
	}
	mbedtls_mpi_init(tmp1);
	mbedtls_mpi_lset(tmp1, 1);

	sae_debug(SAE_DEBUG_MBED, " compare peer scalar and order \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("peer->peer_scalar", peer->peer_scalar);
		pp_a_bignum("peer->grp_def->order", peer->grp_def->order);
	}
	if ((mbedtls_mpi_cmp_mpi(peer->peer_scalar, tmp1) < 1) ||
	    (mbedtls_mpi_cmp_mpi(peer->peer_scalar, peer->grp_def->order) > 0)) {
		sae_debug(SAE_DEBUG_ERR, "peer's scalar is invalid!\n");
		goto process_commit_fail;
	}

	/*
	 * ...and the element
	 */
	//dump_hex("peer->peer_element", peer->peer_element, sizeof(mbedtls_ecp_point));
	sae_debug(SAE_DEBUG_MBED, " check peer element \n");
	if (mbedtls_ecp_check_pubkey(peer->grp_def->group, peer->peer_element) != 0) {
		log(" [5.2.6][4.2.6] peer's element is invalid!\n");
		goto process_commit_fail;
	}

	if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
		pp_a_bignum("peer's scalar", peer->peer_scalar);
		printk("peer's element:\n");
		pp_a_bignum("x", x);
		pp_a_bignum("y", y);
	}

	/*
	 * now compute: scalar * PWE...
	 */
	sae_debug(SAE_DEBUG_MBED, " K = peer_scalar * PWE \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("peer->pwe->X", &peer->pwe->X);
		pp_a_bignum("peer->pwe->Y", &peer->pwe->Y);
		pp_a_bignum("peer->pwe->Z", &peer->pwe->Z);
	}
	mbedtls_mpi_lset(&peer->pwe->Z, 1);
	sae_debug(SAE_DEBUG_MBED, " Setting peer->pwe->Z to 1 \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("peer->pwe->X", &peer->pwe->X);
		pp_a_bignum("peer->pwe->Y", &peer->pwe->Y);
		pp_a_bignum("peer->pwe->Z", &peer->pwe->Z);
	}
	sae_debug(SAE_DEBUG_MBED, " K = peer_calar * PWE \n");

	ret = mbedtls_ecp_mul(peer->grp_def->group, K, peer->peer_scalar, peer->pwe, NULL, NULL);
	if (ret != 0) {
		log("unable to multiply peer's scalar and PWE! %d \n", ret);
		goto process_commit_fail;
	}
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("K->X", &K->X);
		pp_a_bignum("K->Y", &K->Y);
		pp_a_bignum("peer->pwe->X", &peer->pwe->X);
		pp_a_bignum("peer->pwe->Y", &peer->pwe->Y);
	}

	/*
	 * ... + element
	 */
	if (mbedtls_ecp_muladd(peer->grp_def->group, K, tmp1, K, tmp1, peer->peer_element) != 0) {
		log("unable to add element to running point!\n");
		goto process_commit_fail;
	}
	sae_debug(SAE_DEBUG_MBED, " K = K + peer_element \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("K->X", &K->X);
		pp_a_bignum("K->Y", &K->Y);
		pp_a_bignum("K->Z", &K->Z);
	}

	/*
	 * ... * private val = our private_val * peer's private_val * pwe
	 */
	mbedtls_mpi_lset(&K->Z, 1);
	sae_debug(SAE_DEBUG_MBED, " Setting &K->Z to 1 \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("K->X", &K->X);
		pp_a_bignum("K->Y", &K->Y);
		pp_a_bignum("K->Z", &K->Z);
	}

	ret = mbedtls_ecp_mul(peer->grp_def->group, K, peer->private_val, K, NULL, NULL);

	if (ret != 0) {
		log("unable to multiple intermediate by private value! %d \n", ret);
		goto process_commit_fail;
	}

	if (sae_debug_mask & SAE_DEBUG_MBED) {
		log(" K = private_val * K \n");
		pp_a_bignum("K->X", &K->X);
		pp_a_bignum("K->Y", &K->Y);
	}

	k = &K->X;
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("k", k);
	}

	/*
	 * compute the KCK and PMK
	 */
	if ((tmp = kmalloc(mbedtls_mpi_size(peer->grp_def->prime), GFP_ATOMIC)) == NULL) {
		sae_debug(SAE_DEBUG_ERR, "unable to malloc %d bytes for secret!\n", mbedtls_mpi_size(k));
		goto process_commit_fail;
	}
	/*
	 * first extract the entropy from k into keyseed...
	 */
	offset = mbedtls_mpi_size(peer->grp_def->prime) - mbedtls_mpi_size(k);
	memset(tmp, 0, offset);
	mbedtls_mpi_write_binary(k, tmp + offset, mbedtls_mpi_size(k));
	sae_debug(SAE_DEBUG_MBED, " write k to tmp \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("tmp", tmp, mbedtls_mpi_size(peer->grp_def->prime));
	}
	mbedtls_md_init(&ctx);
	mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_md_hmac_starts(&ctx, priv->allzero, MBEDTLS_DIGEST_LENGTH);
	mbedtls_md_hmac_update(&ctx, tmp, mbedtls_mpi_size(peer->grp_def->prime));
	mbedtls_md_hmac_finish(&ctx, keyseed);
	sae_debug(SAE_DEBUG_MBED, " hmac keyseed \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("keyseed", keyseed, MBEDTLS_DIGEST_LENGTH);
	}
	mbedtls_md_free(&ctx);
	kfree(tmp);

	/*
	 * ...then expand it to create KCK | PMK
	 */
	if (((tmp = kmalloc(mbedtls_mpi_size(peer->grp_def->order), GFP_ATOMIC)) == NULL) ||
	    ((nsum = kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC)) == NULL)) {
		sae_debug(SAE_DEBUG_ERR, "unable to create buf/bignum to sum scalars!\n");
		goto process_commit_fail;
	}
	mbedtls_mpi_init(nsum);

	mbedtls_mpi_add_mpi(nsum, peer->my_scalar, peer->peer_scalar);
	sae_debug(SAE_DEBUG_MBED, " nsum= my_scalar+peer_scalar \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("nsum", nsum);
	}

	mbedtls_mpi_mod_mpi(nsum, nsum, peer->grp_def->order);
	sae_debug(SAE_DEBUG_MBED, " nsum = nsum mod order \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("nsum", nsum);
	}

	offset = mbedtls_mpi_size(peer->grp_def->order) - mbedtls_mpi_size(nsum);
	memset(tmp, 0, offset);
	mbedtls_mpi_write_binary(nsum, tmp + offset, (mbedtls_mpi_size(peer->grp_def->order) - offset));
	sae_debug(SAE_DEBUG_MBED, " write nsum to tmp \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("tmp", tmp, mbedtls_mpi_size(peer->grp_def->order));
	}

	memcpy(peer->pmkid, tmp, 16);
	sae_debug(SAE_DEBUG_MBED, " memcpy(peer->pmkid, tmp, 16) \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("peer->pmkid", peer->pmkid, 16);
	}

	prf(keyseed, MBEDTLS_DIGEST_LENGTH,
	    (unsigned char *)"SAE KCK and PMK", strlen("SAE KCK and PMK"),
	    tmp, mbedtls_mpi_size(peer->grp_def->order), kckpmk, ((MBEDTLS_DIGEST_LENGTH * 2) * 8));
	kfree(tmp);

	memcpy(peer->kck, kckpmk, MBEDTLS_DIGEST_LENGTH);
	memcpy(peer->pmk, kckpmk + MBEDTLS_DIGEST_LENGTH, MBEDTLS_DIGEST_LENGTH);

	log("PMKID/PMK/KCK generated");

	if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
		pp_a_bignum("k", k);
		print_buffer("keyseed", keyseed, MBEDTLS_DIGEST_LENGTH);
		print_buffer("KCK", peer->kck, MBEDTLS_DIGEST_LENGTH);
		print_buffer("PMK", peer->pmk, MBEDTLS_DIGEST_LENGTH);
	}
	if (0) {
process_commit_fail:
		ret = -1;
	}
	if (x) {
		mbedtls_mpi_free(x);
		kfree(x);
		x = NULL;
	}
	if (y) {
		mbedtls_mpi_free(y);
		kfree(y);
		y = NULL;
	}
	if (tmp1) {
		mbedtls_mpi_free(tmp1);
		kfree(tmp1);
		tmp1 = NULL;
	}
	if (nsum) {
		mbedtls_mpi_free(nsum);
		kfree(nsum);
		nsum = NULL;
	}
	if (K) {
		mbedtls_ecp_point_free(K);
		kfree(K);
		K = NULL;
	}

	return ret;

}

int prepare_commit_to_peer(
	struct rtl8192cd_priv *priv, u8 * sa, unsigned char *token, int token_len
	,unsigned char *tmp_buf,unsigned char *tmp_len)
{
	struct ieee80211_mgmt_frame *frame;
	int offset1, offset2;
	size_t len = 0;
	mbedtls_mpi *x = NULL, *y = NULL, *mask = NULL;
	unsigned short grp_num;
	unsigned char *ptr = NULL;
	int ret;
	struct candidate *peer = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, sa);
	//memset(tmp_buf, 0, sizeof(tmp_buf));
	frame = (struct ieee80211_mgmt_frame *)tmp_buf;

	//log(" fill in authentication frame header for %pm %d...", sa, peer == NULL);
	//log("deal SAE with %pm",sa);
	/*
	 * fill in authentication frame header...
	 */
	frame->frame_control = ieee_order((IEEE802_11_FC_TYPE_MGMT << 2 | IEEE802_11_FC_STYPE_AUTH << 4));
	memcpy(frame->sa, peer->my_mac, ETH_ALEN);
	memcpy(frame->da, peer->peer_mac, ETH_ALEN);
#if 1
	memcpy(frame->bssid, peer->my_mac, ETH_ALEN);	//rtk-sae
#else
	memcpy(frame->bssid, peer->peer_mac, ETH_ALEN);	//rtk-sae
#endif

	frame->authenticate.alg = ieee_order(SAE_AUTH_ALG);
	frame->authenticate.auth_seq = ieee_order(SAE_AUTH_COMMIT);
	len = IEEE802_11_HDR_LEN + sizeof(frame->authenticate);
	ptr = frame->authenticate.u.var8;

	/*
	 * first, indicate what group we're committing with
	 */
//rtk_sae auth group
	grp_num = ieee_order(peer->grp_def->group_num);
	memcpy(ptr, &grp_num, sizeof(unsigned short));
	sae_debug(SAE_DEBUG_MBED, " ptr \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("ptr", ptr, sizeof(unsigned short));
	}
	ptr += sizeof(unsigned short);
	len += sizeof(unsigned short);

	/*
	 * if we've been asked to include a token then include a token
	 */
//rtk_sae token
	if (token_len && (token != NULL)) {
		memcpy(ptr, token, token_len);
		sae_debug(SAE_DEBUG_MBED, " ptr += sizeof(unsigned short) \n");
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			print_buffer("ptr", ptr, token_len);
		}
		ptr += token_len;
		len += token_len;
	}

	if (peer->private_val == NULL) {
		mask = kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
		if (mask == NULL) {
			sae_debug(SAE_DEBUG_ERR, "unable to commit to peer!\n");
			return -1;
		}
		mbedtls_mpi_init(mask);

		peer->private_val = kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
		if (peer->private_val == NULL) {
			sae_debug(SAE_DEBUG_ERR, "unable to commit to peer!\n");
			if (mask) {
				mbedtls_mpi_free(mask);
				kfree(mask);
				mask = NULL;
			}
			return -1;
		}
		mbedtls_mpi_init(peer->private_val);
		/*
		 * generate private values
		 */
#if 1
		sae_rand_range(peer->private_val, peer->grp_def->order);
		sae_rand_range(mask, peer->grp_def->order);
#else
		mbedtls_mpi_read_binary(peer->private_val, PRIVATE_COPY, 32);
		mbedtls_mpi_read_binary(mask, MASK_COPY, 32);
#endif
		if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
			pp_a_bignum("local private value", peer->private_val);
			pp_a_bignum("local mask value", mask);
		}
		/*
		 * generate scalar = (priv + mask) mod order
		 */
		mbedtls_mpi_add_mpi(peer->my_scalar, peer->private_val, mask);
		sae_debug(SAE_DEBUG_MBED, " peer->my_scalar = priv + mask \n");
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			pp_a_bignum("peer->my_scalar", peer->my_scalar);
		}
		mbedtls_mpi_mod_mpi(peer->my_scalar, peer->my_scalar, peer->grp_def->order);
		sae_debug(SAE_DEBUG_MBED, " peer->my_scalar = peer->my_scalar mod order \n");
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			pp_a_bignum("peer->my_scalar", peer->my_scalar);
		}

		/*
		 * generate element = -(mask*pwe)
		 */
		if (peer->my_element == NULL) {
			sae_debug(SAE_DEBUG_MBED, " my_element is NULL \n");
			peer->my_element = (mbedtls_ecp_point *) kmalloc(sizeof(mbedtls_ecp_point), GFP_ATOMIC);
			if (peer->my_element == NULL) {
				sae_debug(SAE_DEBUG_ERR, "can't create mbedtls_ecp_point!\n");
				kfree(mask);
				return -1;
			}
			mbedtls_ecp_point_init(peer->my_element);
		}
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			pp_a_bignum("peer->pwe->X", &peer->pwe->X);
			pp_a_bignum("peer->pwe->Y", &peer->pwe->Y);
			pp_a_bignum("peer->pwe->Z", &peer->pwe->Z);
		}
		mbedtls_mpi_lset(&peer->pwe->Z, 1);
		sae_debug(SAE_DEBUG_MBED, " Setting peer->pwe->Z to 1 \n");
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			pp_a_bignum("peer->pwe->X", &peer->pwe->X);
			pp_a_bignum("peer->pwe->Y", &peer->pwe->Y);
			pp_a_bignum("peer->pwe->Z", &peer->pwe->Z);
		}

		ret = mbedtls_ecp_mul(peer->grp_def->group, peer->my_element, mask, peer->pwe, NULL, NULL);
		if (ret != 0) {
			sae_debug(SAE_DEBUG_ERR, "unable to compute A! %d \n", ret);
			if (mask) {
				mbedtls_mpi_free(mask);
				kfree(mask);
				mask = NULL;
			}
			if (peer->private_val) {
				mbedtls_mpi_free(peer->private_val);
				kfree(peer->private_val);
				peer->private_val = NULL;
			}
			return -1;
		}
		sae_debug(SAE_DEBUG_MBED, " peer->my_element = mask*pwe \n");
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			pp_a_bignum("peer->my_element->X", &peer->my_element->X);
			pp_a_bignum("peer->my_element->Y", &peer->my_element->Y);
		}
		if (tmp_ecp_safe_invert_jac(peer->grp_def->group, peer->my_element, 1) != 0) {
			sae_debug(SAE_DEBUG_ERR, "unable to invert A!\n");
			if (mask) {
				mbedtls_mpi_free(mask);
				kfree(mask);
				mask = NULL;
			}
			if (peer->private_val) {
				mbedtls_mpi_free(peer->private_val);
				kfree(peer->private_val);
				peer->private_val = NULL;
			}
			return -1;
		}
		if (mask) {
			mbedtls_mpi_free(mask);
			kfree(mask);
			mask = NULL;
		}
	}

	x = &peer->my_element->X;
	y = &peer->my_element->Y;

	if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
		printk("local commit:\n");
		pp_a_bignum("my scalar", peer->my_scalar);
		printk("my element:\n");
		pp_a_bignum("x", x);
		pp_a_bignum("y", y);
	}
	/*
	 * fill in the commit, first in the commit message is the scalar
	 */
	offset1 = mbedtls_mpi_size(peer->grp_def->order) - mbedtls_mpi_size(peer->my_scalar);
	mbedtls_mpi_write_binary(peer->my_scalar, ptr + offset1, mbedtls_mpi_size(peer->my_scalar));
	sae_debug(SAE_DEBUG_MBED, " ptr = ptr + sizeof(unsigned short) + token_len \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("ptr", ptr, mbedtls_mpi_size(peer->grp_def->order));
	}
	ptr += mbedtls_mpi_size(peer->grp_def->order);
	len += mbedtls_mpi_size(peer->grp_def->order);

	/*
	 * ...next is the element, x then y
	 */
	x = &peer->my_element->X;
	y = &peer->my_element->Y;

	sae_debug(SAE_DEBUG_MBED, " my_element \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("x", x);
		pp_a_bignum("y", y);
	}

	offset1 = mbedtls_mpi_size(peer->grp_def->prime) - mbedtls_mpi_size(x);
	mbedtls_mpi_write_binary(x, ptr + offset1, mbedtls_mpi_size(x));
	sae_debug(SAE_DEBUG_MBED,
		  " ptr = ptr+sizeof(unsigned short)+token_len+mbedtls_mpi_size(peer->grp_def->order) \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("ptr", ptr, mbedtls_mpi_size(peer->grp_def->prime));
	}
	ptr += mbedtls_mpi_size(peer->grp_def->prime);

	offset2 = mbedtls_mpi_size(peer->grp_def->prime) - mbedtls_mpi_size(y);
	mbedtls_mpi_write_binary(y, ptr + offset2, mbedtls_mpi_size(y));
	sae_debug(SAE_DEBUG_MBED,
		  " ptr = ptr+sizeof(unsigned short)+token_len+mbedtls_mpi_size(peer->grp_def->order)+mbedtls_mpi_size(peer->grp_def->prime) \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("ptr", ptr, mbedtls_mpi_size(peer->grp_def->prime));
	}
	ptr += mbedtls_mpi_size(peer->grp_def->prime);
	len += (2 * mbedtls_mpi_size(peer->grp_def->prime));

	log("sending[%s] to peer[%pm][%s]  (%s token), len[%d] group[%d]",
		state_to_string(peer->state),peer->peer_mac,
	    seq_to_string(ieee_order(frame->authenticate.auth_seq)),
	    (token_len ? "with" : "no"), len, peer->grp_def->group_num);

	*tmp_len = len;

	return 0;
}

int send_commit_to_peer(struct rtl8192cd_priv *priv, u8 * sa, u8 * frame, int len)
{
	struct candidate *peer = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, sa);
	if (peer && issue_sae_frame(priv, (u8 *) frame, len) != 0) {
		log("can't send an authentication frame to %pm\n", peer->peer_mac);
		if (peer->private_val) {
			mbedtls_mpi_free(peer->private_val);
			kfree(peer->private_val);
			peer->private_val = NULL;
		}
		return -1;
	}

	return 0;
}

static int commit_to_peer(struct rtl8192cd_priv *priv, u8 * sa, unsigned char *token, int token_len)	//rtk_sae token
{
	char buf[2048];
	struct ieee80211_mgmt_frame *frame;
	int offset1, offset2;
	size_t len = 0;
	mbedtls_mpi *x = NULL, *y = NULL, *mask = NULL;
	unsigned short grp_num;
	unsigned char *ptr = NULL;
	int ret;
	struct candidate *peer = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, sa);
	if (peer == NULL) {
		log("peer==NULL,CHK!!");
	}
	memset(buf, 0, sizeof(buf));
	frame = (struct ieee80211_mgmt_frame *)buf;

	//panic_printk("commit_to_peer ++ \n");

	//log("fill in auth for [%pm] peer=[%d]", sa, peer == NULL);
	/*
	 * fill in authentication frame header...
	 */
	frame->frame_control = ieee_order((IEEE802_11_FC_TYPE_MGMT << 2 | IEEE802_11_FC_STYPE_AUTH << 4));
	memcpy(frame->sa, peer->my_mac, ETH_ALEN);
	memcpy(frame->da, peer->peer_mac, ETH_ALEN);

	if (OPMODE & WIFI_AP_STATE)
		memcpy(frame->bssid, peer->my_mac, ETH_ALEN);	//rtk-sae
	else
		memcpy(frame->bssid, peer->peer_mac, ETH_ALEN);	//rtk-sae

	frame->authenticate.alg = ieee_order(SAE_AUTH_ALG);
	frame->authenticate.auth_seq = ieee_order(SAE_AUTH_COMMIT);
	len = IEEE802_11_HDR_LEN + sizeof(frame->authenticate);
	ptr = frame->authenticate.u.var8;

	/*
	 * first, indicate what group we're committing with
	 */
//rtk_sae auth group
	grp_num = ieee_order(peer->grp_def->group_num);
	memcpy(ptr, &grp_num, sizeof(unsigned short));
	sae_debug(SAE_DEBUG_MBED, " ptr \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("ptr", ptr, sizeof(unsigned short));
	}
	ptr += sizeof(unsigned short);
	len += sizeof(unsigned short);

	/*
	 * if we've been asked to include a token then include a token
	 */
//rtk_sae token
	if (token_len && (token != NULL)) {
		memcpy(ptr, token, token_len);
		dump_hex("token", token, token_len);
		sae_debug(SAE_DEBUG_MBED, " ptr += sizeof(unsigned short) \n");
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			print_buffer("ptr", ptr, token_len);
		}
		ptr += token_len;
		len += token_len;
	}

	if (peer->private_val == NULL) {
		mask = kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
		if (mask == NULL) {
			sae_debug(SAE_DEBUG_ERR, "unable to commit to peer!\n");
			return -1;
		}
		mbedtls_mpi_init(mask);

		peer->private_val = kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
		if (peer->private_val == NULL) {
			sae_debug(SAE_DEBUG_ERR, "unable to commit to peer!\n");
			if (mask) {
				mbedtls_mpi_free(mask);
				kfree(mask);
				mask = NULL;
			}
			return -1;
		}
		mbedtls_mpi_init(peer->private_val);
		/*
		 * generate private values
		 */
#if 1
		sae_rand_range(peer->private_val, peer->grp_def->order);
		sae_rand_range(mask, peer->grp_def->order);
#else
		mbedtls_mpi_read_binary(peer->private_val, PRIVATE_COPY, 32);
		mbedtls_mpi_read_binary(mask, MASK_COPY, 32);
#endif
		if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
			pp_a_bignum("local private value", peer->private_val);
			pp_a_bignum("local mask value", mask);
		}
		/*
		 * generate scalar = (priv + mask) mod order
		 */
		mbedtls_mpi_add_mpi(peer->my_scalar, peer->private_val, mask);
		sae_debug(SAE_DEBUG_MBED, " peer->my_scalar = priv + mask \n");
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			pp_a_bignum("peer->my_scalar", peer->my_scalar);
		}
		mbedtls_mpi_mod_mpi(peer->my_scalar, peer->my_scalar, peer->grp_def->order);
		sae_debug(SAE_DEBUG_MBED, " peer->my_scalar = peer->my_scalar mod order \n");
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			pp_a_bignum("peer->my_scalar", peer->my_scalar);
		}

		/*
		 * generate element = -(mask*pwe)
		 */
		if (peer->my_element == NULL) {
			sae_debug(SAE_DEBUG_MBED, " my_element is NULL \n");
			peer->my_element = (mbedtls_ecp_point *) kmalloc(sizeof(mbedtls_ecp_point), GFP_ATOMIC);
			if (peer->my_element == NULL) {
				sae_debug(SAE_DEBUG_ERR, "can't create mbedtls_ecp_point!\n");
				kfree(mask);
				return -1;
			}
			mbedtls_ecp_point_init(peer->my_element);
		}
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			pp_a_bignum("peer->pwe->X", &peer->pwe->X);
			pp_a_bignum("peer->pwe->Y", &peer->pwe->Y);
			pp_a_bignum("peer->pwe->Z", &peer->pwe->Z);
		}
		mbedtls_mpi_lset(&peer->pwe->Z, 1);
		sae_debug(SAE_DEBUG_MBED, " Setting peer->pwe->Z to 1 \n");
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			pp_a_bignum("peer->pwe->X", &peer->pwe->X);
			pp_a_bignum("peer->pwe->Y", &peer->pwe->Y);
			pp_a_bignum("peer->pwe->Z", &peer->pwe->Z);
		}

		ret = mbedtls_ecp_mul(peer->grp_def->group, peer->my_element, mask, peer->pwe, NULL, NULL);
		if (ret != 0) {
			sae_debug(SAE_DEBUG_ERR, "unable to compute A! %d \n", ret);
			if (mask) {
				mbedtls_mpi_free(mask);
				kfree(mask);
				mask = NULL;
			}
			if (peer->private_val) {
				mbedtls_mpi_free(peer->private_val);
				kfree(peer->private_val);
				peer->private_val = NULL;
			}
			return -1;
		}
		sae_debug(SAE_DEBUG_MBED, " peer->my_element = mask*pwe \n");
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			pp_a_bignum("peer->my_element->X", &peer->my_element->X);
			pp_a_bignum("peer->my_element->Y", &peer->my_element->Y);
		}
		if (tmp_ecp_safe_invert_jac(peer->grp_def->group, peer->my_element, 1) != 0) {
			sae_debug(SAE_DEBUG_ERR, "unable to invert A!\n");
			if (mask) {
				mbedtls_mpi_free(mask);
				kfree(mask);
				mask = NULL;
			}
			if (peer->private_val) {
				mbedtls_mpi_free(peer->private_val);
				kfree(peer->private_val);
				peer->private_val = NULL;
			}
			return -1;
		}
		if (mask) {
			mbedtls_mpi_free(mask);
			kfree(mask);
			mask = NULL;
		}
	}

	x = &peer->my_element->X;
	y = &peer->my_element->Y;

	if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
		log("local commit:");
		pp_a_bignum("my scalar", peer->my_scalar);
		log("my element:");
		pp_a_bignum("x", x);
		pp_a_bignum("y", y);
	}
	/*
	 * fill in the commit, first in the commit message is the scalar
	 */
	offset1 = mbedtls_mpi_size(peer->grp_def->order) - mbedtls_mpi_size(peer->my_scalar);
	mbedtls_mpi_write_binary(peer->my_scalar, ptr + offset1, mbedtls_mpi_size(peer->my_scalar));
	sae_debug(SAE_DEBUG_MBED, " ptr = ptr + sizeof(unsigned short) + token_len \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("ptr", ptr, mbedtls_mpi_size(peer->grp_def->order));
	}
	ptr += mbedtls_mpi_size(peer->grp_def->order);
	len += mbedtls_mpi_size(peer->grp_def->order);

	/*
	 * ...next is the element, x then y
	 */
	x = &peer->my_element->X;
	y = &peer->my_element->Y;

	sae_debug(SAE_DEBUG_MBED, " my_element \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("x", x);
		pp_a_bignum("y", y);
	}

	offset1 = mbedtls_mpi_size(peer->grp_def->prime) - mbedtls_mpi_size(x);
	mbedtls_mpi_write_binary(x, ptr + offset1, mbedtls_mpi_size(x));
	sae_debug(SAE_DEBUG_MBED,
		  " ptr = ptr+sizeof(unsigned short)+token_len+mbedtls_mpi_size(peer->grp_def->order) \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("ptr", ptr, mbedtls_mpi_size(peer->grp_def->prime));
	}
	ptr += mbedtls_mpi_size(peer->grp_def->prime);

	offset2 = mbedtls_mpi_size(peer->grp_def->prime) - mbedtls_mpi_size(y);
	mbedtls_mpi_write_binary(y, ptr + offset2, mbedtls_mpi_size(y));
	sae_debug(SAE_DEBUG_MBED,
		  " ptr = ptr+sizeof(unsigned short)+token_len+mbedtls_mpi_size(peer->grp_def->order)+mbedtls_mpi_size(peer->grp_def->prime) \n");
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		print_buffer("ptr", ptr, mbedtls_mpi_size(peer->grp_def->prime));
	}
	ptr += mbedtls_mpi_size(peer->grp_def->prime);
	len += (2 * mbedtls_mpi_size(peer->grp_def->prime));

	log("\n peer[%pm] in[%s] sending[%s (%s token)],len[%d],group[%d]",
	    peer->peer_mac,
	    state_to_string(peer->state),
	    seq_to_string(ieee_order(frame->authenticate.auth_seq)),
	    (token_len ? "with" : "no"), len, peer->grp_def->group_num);

	//dump_hex("we will send out..", frame, 128);
	//log("issue_sae_frame");
	if (issue_sae_frame(priv, (u8 *) frame, len) != 0) {
		log("can't send an authentication frame to %pm\n", peer->peer_mac);
		if (peer->private_val) {
			mbedtls_mpi_free(peer->private_val);
			kfree(peer->private_val);
			peer->private_val = NULL;
		}
		return -1;
	}
	return 0;
}

static int request_token(struct rtl8192cd_priv *priv, struct ieee80211_mgmt_frame *req, unsigned char *me, struct candidate *peer)	//rtk_sae
{
	char buf[2048];
	struct ieee80211_mgmt_frame *frame;
	mbedtls_md_context_t ctx;
	size_t len = 0;

	unsigned short grp_num;
	unsigned char *ptr;
	memset(buf, 0, sizeof(buf));
	frame = (struct ieee80211_mgmt_frame *)buf;
	frame->frame_control = ieee_order((IEEE802_11_FC_TYPE_MGMT << 2 | IEEE802_11_FC_STYPE_AUTH << 4));
	memcpy(frame->sa, me, ETH_ALEN);
	memcpy(frame->da, req->sa, ETH_ALEN);

	if (OPMODE & WIFI_AP_STATE)	//rtk_sae
		memcpy(frame->bssid, me, ETH_ALEN);
	else
		memcpy(frame->bssid, req->sa, ETH_ALEN);

	frame->authenticate.alg = req->authenticate.alg;
	frame->authenticate.auth_seq = ieee_order(SAE_AUTH_COMMIT);
	frame->authenticate.status = ieee_order(WLAN_STATUS_ANTI_CLOGGING_TOKEN_NEEDED);
	len = IEEE802_11_HDR_LEN + sizeof(frame->authenticate);

	ptr = frame->authenticate.u.var8;

	if (peer)
		grp_num = ieee_order(peer->grp_def->group_num);
	else
		grp_num = ieee_order(priv->pmib->dot1180211AuthEntry.dot11SAEGroup);

	memcpy(ptr, &grp_num, sizeof(unsigned short));
	ptr += sizeof(unsigned short);
	len += sizeof(unsigned short);

	mbedtls_md_init(&ctx);
	mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	mbedtls_md_hmac_starts(&ctx, (unsigned char *)&priv->token_generator, sizeof(unsigned long));	//need to verify
	mbedtls_md_hmac_update(&ctx, req->sa, ETH_ALEN);
	mbedtls_md_hmac_update(&ctx, me, ETH_ALEN);
	mbedtls_md_hmac_finish(&ctx, ptr);

	//log("Calling mbedtls_md_hmac_finish\n");
	if (1) {
		print_buffer("token", ptr, MBEDTLS_DIGEST_LENGTH);
	}
	mbedtls_md_free(&ctx);
	len += MBEDTLS_DIGEST_LENGTH;

	log("sending a token request to %pm\n", req->sa);
	//log("issue_sae_frame");
	if (issue_sae_frame(priv, buf, len) != 0) {
		log("can't send a rejection frame to %pm \n", req->sa);
		return -1;
	}
	return len;
}

static int reject_to_peer(struct rtl8192cd_priv *priv, struct candidate *peer, struct ieee80211_mgmt_frame *frame)
{
	char buf[2048];
	struct ieee80211_mgmt_frame *rej = NULL;
	size_t len = 0;

	memset(buf, 0, sizeof(buf));
	rej = (struct ieee80211_mgmt_frame *)buf;
	rej->frame_control = ieee_order((IEEE802_11_FC_TYPE_MGMT << 2 | IEEE802_11_FC_STYPE_AUTH << 4));
	memcpy(rej->sa, peer->my_mac, ETH_ALEN);
	memcpy(rej->da, peer->peer_mac, ETH_ALEN);
	memcpy(rej->bssid, peer->peer_mac, ETH_ALEN);

	rej->authenticate.alg = frame->authenticate.alg;	/* no need for order conversion */
	rej->authenticate.auth_seq = ieee_order(SAE_AUTH_COMMIT);
	rej->authenticate.status = ieee_order(WLAN_STATUS_NOT_SUPPORTED_GROUP);
	len = IEEE802_11_HDR_LEN + sizeof(rej->authenticate);

	/*
	 * indicate what we're rejecting
	 */
	memcpy(rej->authenticate.u.var8, frame->authenticate.u.var8, sizeof(unsigned long));
	len += sizeof(unsigned long);

	log("sending REJECTION to %pm\n", peer->peer_mac);
	//log2("issue_sae_frame");
	if (issue_sae_frame(priv, buf, len) != 0) {
		log("can't send an authentication frame to %pm \n", peer->peer_mac);
		return -1;
	}

	return 0;
}

/*
 * calculate the legendre symbol (a/p)
 */
static int legendre(mbedtls_mpi * a, mbedtls_mpi * p, mbedtls_mpi * exp)
{
	mbedtls_mpi *tmp = NULL, *r = NULL;
	int symbol = -1;

	tmp = kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (tmp == NULL) {
		sae_debug(SAE_DEBUG_ERR, "unable to malloc space for mbedtls_mpi buffer!\n");
		return symbol;
	} else {
		mbedtls_mpi_init(tmp);
		r = kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
		if (r == NULL) {
			sae_debug(SAE_DEBUG_ERR, "unable to malloc space for mbedtls_mpi buffer!\n");
			return symbol;
		} else {
			mbedtls_mpi_init(r);
			mbedtls_mpi_exp_mod(r, a, exp, p, tmp);
			sae_debug(SAE_DEBUG_MBED, " tmp = a^exp \n");
			if (sae_debug_mask & SAE_DEBUG_MBED) {
				pp_a_bignum("r", r);
			}

			if (mbedtls_mpi_cmp_int(r, 1) == 0)
				symbol = 1;
			else if (mbedtls_mpi_cmp_int(r, 0) == 0)
				symbol = 0;
			else
				symbol = -1;

			mbedtls_mpi_free(tmp);
			kfree(tmp);
			mbedtls_mpi_free(r);
			kfree(r);
		}
	}
	return symbol;
}

/*
 * assign_group_tp_peer()
 *      The group has been selected, assign it to the peer and create PWE.
 */
static int assign_group_to_peer(struct rtl8192cd_priv *priv, GD * grp, u8 * sa)
{
	mbedtls_md_context_t ctx;
	mbedtls_mpi *x_candidate = NULL, *y_candidate = NULL, *x = NULL, *y = NULL, *rnd = NULL, *qr = NULL, *qnr =
	    NULL;
	mbedtls_mpi *pm1 = NULL, *pm1d2 = NULL, *tmp1 = NULL, *tmp2 = NULL, *tmp3 = NULL, *a = NULL, *b = NULL;
	unsigned char pwe_digest[MBEDTLS_DIGEST_LENGTH], addrs[ETH_ALEN * 2], ctr;
	unsigned char *prfbuf = NULL, *primebuf = NULL;
	int primebitlen, is_odd, check, found = 0;
	struct candidate *peer = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, sa);

	/*
	 * allow for replacement of group....
	 */
	if (peer->pwe) {
		mbedtls_ecp_point_free(peer->pwe);
		free(peer->pwe);
		peer->pwe = NULL;
	}
	if (peer->peer_element) {
		mbedtls_ecp_point_free(peer->peer_element);
		free(peer->peer_element);
		peer->peer_element = NULL;
	}
	if (peer->my_element) {
		mbedtls_ecp_point_free(peer->my_element);
		free(peer->my_element);
		peer->my_element = NULL;
	}
	if (peer->private_val) {
		mbedtls_mpi_free(peer->private_val);
		free(peer->private_val);
		peer->private_val = NULL;
	}

	a = (mbedtls_mpi *) kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (a == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't create bignum for candidate!\n");
		goto assign_group_to_peer_fail;
	}
	mbedtls_mpi_init(a);

	rnd = (mbedtls_mpi *) kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (rnd == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't create bignum for candidate!\n");
		goto assign_group_to_peer_fail;
	}
	mbedtls_mpi_init(rnd);

	pm1d2 = (mbedtls_mpi *) kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (pm1d2 == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't create bignum for candidate!\n");
		goto assign_group_to_peer_fail;
	}
	mbedtls_mpi_init(pm1d2);

	pm1 = (mbedtls_mpi *) kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (pm1 == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't create bignum for candidate!\n");
		goto assign_group_to_peer_fail;
	}
	mbedtls_mpi_init(pm1);

	tmp1 = (mbedtls_mpi *) kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (tmp1 == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't create bignum for candidate!\n");
		goto assign_group_to_peer_fail;
	}
	mbedtls_mpi_init(tmp1);

	tmp2 = (mbedtls_mpi *) kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (tmp2 == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't create bignum for candidate!\n");
		goto assign_group_to_peer_fail;
	}
	mbedtls_mpi_init(tmp2);

	tmp3 = (mbedtls_mpi *) kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (tmp3 == NULL) {
		sae_debug(SAE_DEBUG_ERR, "unable to malloc space for mbedtls_mpi buffer!\n");
		goto assign_group_to_peer_fail;
	}
	mbedtls_mpi_init(tmp3);

	qr = (mbedtls_mpi *) kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (qr == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't create bignum for candidate!\n");
		goto assign_group_to_peer_fail;
	}
	mbedtls_mpi_init(qr);

	qnr = (mbedtls_mpi *) kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (qnr == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't create bignum for candidate!\n");
		goto assign_group_to_peer_fail;
	}
	mbedtls_mpi_init(qnr);

	x_candidate = (mbedtls_mpi *) kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (x_candidate == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't create bignum for candidate!\n");
		goto assign_group_to_peer_fail;
	}
	mbedtls_mpi_init(x_candidate);

	y_candidate = (mbedtls_mpi *) kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (y_candidate == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't create bignum for candidate!\n");
		goto assign_group_to_peer_fail;
	}
	mbedtls_mpi_init(y_candidate);

	peer->grp_def = grp;

	peer->pwe = (mbedtls_ecp_point *) kmalloc(sizeof(mbedtls_ecp_point), GFP_ATOMIC);
	if (peer->pwe == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't create mbedtls_ecp_point!\n");
		goto assign_group_to_peer_fail;
	}
	mbedtls_ecp_point_init(peer->pwe);

	peer->peer_element = (mbedtls_ecp_point *) kmalloc(sizeof(mbedtls_ecp_point), GFP_ATOMIC);
	if (peer->peer_element == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't create mbedtls_ecp_point!\n");
		goto assign_group_to_peer_fail;
	}
	mbedtls_ecp_point_init(peer->peer_element);

	peer->my_element = (mbedtls_ecp_point *) kmalloc(sizeof(mbedtls_ecp_point), GFP_ATOMIC);
	if (peer->my_element == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't create mbedtls_ecp_point!\n");
		goto assign_group_to_peer_fail;
	}
	mbedtls_ecp_point_init(peer->my_element);

	if ((prfbuf = (unsigned char *)kmalloc(mbedtls_mpi_size(grp->prime), GFP_ATOMIC)) == NULL) {
		sae_debug(SAE_DEBUG_ERR, "unable to malloc space for prf buffer!\n");
		goto assign_group_to_peer_fail;
	}
	if ((primebuf = (unsigned char *)kmalloc(mbedtls_mpi_size(grp->prime), GFP_ATOMIC)) == NULL) {
		sae_debug(SAE_DEBUG_ERR, "unable to malloc space for prime!\n");
		goto assign_group_to_peer_fail;
	}

	mbedtls_mpi_write_binary(grp->prime, primebuf, mbedtls_mpi_size(grp->prime));
	primebitlen = mbedtls_mpi_bitlen(grp->prime);
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		sae_debug(SAE_DEBUG_MBED, " prime\n");
		pp_a_bignum("prime", grp->prime);
	}

	mbedtls_mpi_lset(tmp2, 3);	//set tmp2 = 3
	mbedtls_mpi_sub_mpi(a, grp->prime, tmp2);	//a=p-3

	b = &grp->group->B;
	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("tmp2 = 3", tmp2);
		sae_debug(SAE_DEBUG_MBED, "a ");
		pp_a_bignum("a", a);
		sae_debug(SAE_DEBUG_MBED, "b");
		pp_a_bignum("b", b);
	}

	sae_debug(SAE_DEBUG_MBED, "Calculate pm1d2=(p-1)/2, tmp2=(p-1)%2\n");
	mbedtls_mpi_lset(tmp2, 1);	//set tmp2 = 1

	if (sae_debug_mask & SAE_DEBUG_MBED) {
		sae_debug(SAE_DEBUG_MBED, "set tmp2 = 1 \n");
		pp_a_bignum("tmp2", tmp2);
	}

	mbedtls_mpi_sub_mpi(pm1, grp->prime, tmp2);	//pm1=p-1

	if (sae_debug_mask & SAE_DEBUG_MBED) {
		sae_debug(SAE_DEBUG_MBED, "set pm1=p-1 \n");
		pp_a_bignum("pm1", pm1);
	}

	mbedtls_mpi_add_mpi(tmp1, tmp2, tmp2);	//tmp1=2

	if (sae_debug_mask & SAE_DEBUG_MBED) {
		sae_debug(SAE_DEBUG_MBED, "tmp1 = 2 \n");
		pp_a_bignum("tmp1", tmp1);
	}

	mbedtls_mpi_div_mpi(pm1d2, tmp2, pm1, tmp1);	//pm1d2=(p-1)/2, tmp2=(p-1)%2

	if (sae_debug_mask & SAE_DEBUG_MBED) {
		sae_debug(SAE_DEBUG_MBED, " pm1d2 = (p-1)/2 \n");
		pp_a_bignum("pm1d2", pm1d2);
	}

	/*
	 * generate a random quadratic residue modulo p and a random
	 * quadratic non-residue modulo p.
	 */

	sae_debug(SAE_DEBUG_MBED, "Generating qr and qnr\n");
#if 1
	do {
		sae_rand_range(qr, pm1);
	}
	while (legendre(qr, grp->prime, pm1d2) != 1);
#else				//for testing
	mbedtls_mpi_read_binary(qr, QR_COPY, 32);
#endif

	if (sae_debug_mask & SAE_DEBUG_MBED) {
		sae_debug(SAE_DEBUG_MBED, "qr \n");
		pp_a_bignum("qr", qr);
	}
#if 1
	do {
		sae_rand_range(qnr, pm1);
	}
	while (legendre(qnr, grp->prime, pm1d2) != -1);
#else				//for testing
	mbedtls_mpi_read_binary(qnr, QNR_COPY, 32);
#endif

	if (sae_debug_mask & SAE_DEBUG_MBED) {
		sae_debug(SAE_DEBUG_MBED, " qnr \n");
		pp_a_bignum("qnr", qnr);
	}
	memset(prfbuf, 0, mbedtls_mpi_size(grp->prime));

	sae_debug(SAE_DEBUG_CRYPTO, "computing PWE on %d bit curve number %d\n", primebitlen, grp->group_num);
	ctr = 0;

	while (ctr < 40) {
		ctr++;
		/*
		 * compute counter-mode password value and stretch to prime
		 */
		if (memcmp(sa, GET_MY_HWADDR, ETH_ALEN) > 0) {
			//if (memcmp(peer->hwaddr, TMP_MY_MAC, ETH_ALEN) > 0) {
			memcpy(addrs, sa, ETH_ALEN);
			memcpy(addrs + ETH_ALEN, GET_MY_HWADDR, ETH_ALEN);
			//memcpy(addrs+ETH_ALEN, TMP_MY_MAC, ETH_ALEN);
		} else {
			memcpy(addrs, GET_MY_HWADDR, ETH_ALEN);
			//memcpy(addrs, TMP_MY_MAC, ETH_ALEN);
			memcpy(addrs + ETH_ALEN, sa, ETH_ALEN);
		}

		if (sae_debug_mask & SAE_DEBUG_MBED) {
			print_buffer("addrs", addrs, (ETH_ALEN * 2));
		}

		mbedtls_md_init(&ctx);
		mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
		mbedtls_md_hmac_starts(&ctx, addrs, (ETH_ALEN * 2));	//need to verify
		mbedtls_md_hmac_update(&ctx, (grp->password), strlen(grp->password));

		//dump_hex("SAE Password:", grp->password, strlen(grp->password));
		mbedtls_md_hmac_update(&ctx, &ctr, sizeof(ctr));
		mbedtls_md_hmac_finish(&ctx, pwe_digest);
		sae_debug(SAE_DEBUG_MBED, " H_Final pwe_digest\n");
		mbedtls_md_free(&ctx);

		if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
			if (memcmp(sa, GET_MY_HWADDR, ETH_ALEN) > 0) {
				//if (memcmp(peer->hwaddr, TMP_MY_MAC, ETH_ALEN) > 0) {
				log("H( %pm  | %pm, %s | %d)\n", sa, GET_MY_HWADDR, grp->password, ctr);
				//MAC_ARG(peer->hwaddr), MAC_ARG(TMP_MY_MAC), grp->password, ctr);
			} else {
				log("H( %pm  | %pm, %s | %d)\n", GET_MY_HWADDR, sa, grp->password, ctr);
				//MAC_ARG(TMP_MY_MAC), MAC_ARG(peer->hwaddr), grp->password, ctr);
			}
			dump_hex("pwe_digest",pwe_digest, MBEDTLS_DIGEST_LENGTH);
		}

		mbedtls_mpi_read_binary(rnd, pwe_digest, MBEDTLS_DIGEST_LENGTH);
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			sae_debug(SAE_DEBUG_MBED, " rnd");
			pp_a_bignum("rnd", rnd);
		}

		prf(pwe_digest, MBEDTLS_DIGEST_LENGTH,
		    (unsigned char *)"SAE Hunting and Pecking", strlen("SAE Hunting and Pecking"),
		    primebuf, mbedtls_mpi_size(grp->prime), prfbuf, primebitlen);
		mbedtls_mpi_read_binary(x_candidate, prfbuf, mbedtls_mpi_size(grp->prime));
		sae_debug(SAE_DEBUG_MBED, " prf result to bn\n");

		/*
		 * prf() returns a string of bits 0..primebitlen, but BN_bin2bn will
		 * treat that string of bits as a big-endian number. If the primebitlen
		 * is not an even multiple of 8 we masked off the excess bits-- those
		 * _after_ primebitlen-- in prf() so now interpreting this as a
		 * big-endian number is wrong. We have to shift right the amount we
		 * masked off.
		 */
		if (primebitlen % 8) {
			mbedtls_mpi_shift_r(x_candidate, (8 - (primebitlen % 8)));
		}

		/*
		 * if this candidate value is greater than the prime then try again
		 */
		if (mbedtls_mpi_cmp_abs(x_candidate, grp->prime) >= 0) {
			continue;
		}

		if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
			memset(prfbuf, 0, mbedtls_mpi_size(grp->prime));
			mbedtls_mpi_write_binary(x_candidate,
						 prfbuf + (mbedtls_mpi_size(grp->prime) -
							   mbedtls_mpi_size(x_candidate)),
						 mbedtls_mpi_size(x_candidate));
			print_buffer("candidate x value", prfbuf, mbedtls_mpi_size(grp->prime));
		}

		/*
		 * compute y^2 using the equation of the curve
		 *
		 *              y^2 = x^3 + ax + b
		 */

		sae_debug(SAE_DEBUG_MBED, " Compute y^2 = x^3 + ax + b with count %d \n", ctr);
		mbedtls_mpi_lset(tmp3, 3);	//set tmp3 = 3
		mbedtls_mpi_exp_mod(tmp1, x_candidate, tmp3, grp->prime, NULL);	//tmp1=x_candidte^tmp3 mod prime

		if (sae_debug_mask & SAE_DEBUG_MBED) {
			sae_debug(SAE_DEBUG_MBED, " tmp1 = x^3 \n");
			pp_a_bignum("tmp1", tmp1);
		}

		mbedtls_mpi_mul_mpi(tmp3, a, x_candidate);	//tmp3 = a * x_candidate
		mbedtls_mpi_mod_mpi(tmp2, tmp3, grp->prime);	//tmp1=tmp3 mod prime

		if (sae_debug_mask & SAE_DEBUG_MBED) {
			sae_debug(SAE_DEBUG_MBED, " tmp2 = ax\n");
			pp_a_bignum("tmp2", tmp2);
		}

		mbedtls_mpi_add_mpi(tmp3, tmp1, tmp2);	//tmp3=tmp2+tmp1
		mbedtls_mpi_mod_mpi(tmp2, tmp3, grp->prime);	//tmp2=tmp3 mod prime

		if (sae_debug_mask & SAE_DEBUG_MBED) {
			sae_debug(SAE_DEBUG_MBED, " tmp2 = x^3 + ax \n");
			pp_a_bignum("tmp2", tmp2);
		}

		mbedtls_mpi_add_mpi(tmp3, tmp2, b);	//tmp3=tmp2+b
		mbedtls_mpi_mod_mpi(tmp2, tmp3, grp->prime);	//tmp2=tmp3 mod prime

		if (sae_debug_mask & SAE_DEBUG_MBED) {
			sae_debug(SAE_DEBUG_MBED, " tmp2 = x^3 + ax + b \n");
			pp_a_bignum("tmp2", tmp2);
		}
		mbedtls_mpi_copy(y_candidate, tmp2);

		/*
		 * mask tmp2 so doing legendre won't leak timing info
		 *
		 * tmp1 is a random number between 1 and p-1
		 */
		sae_debug(SAE_DEBUG_MBED, " Mask y^2 \n");
#if 1
		sae_rand_range(tmp1, pm1);
#else
		if (ctr == 1)
			mbedtls_mpi_read_binary(tmp1, TMP1_COPY, 32);
		else
			mbedtls_mpi_read_binary(tmp1, TMP2_COPY, 32);

#endif

		if (sae_debug_mask & SAE_DEBUG_MBED) {
			sae_debug(SAE_DEBUG_MBED, " ramdom tmp1 \n");
			pp_a_bignum("tmp1", tmp1);
		}

		mbedtls_mpi_mul_mpi(tmp3, tmp2, tmp1);	//tmp3=tmp2 * tmp1
		mbedtls_mpi_mod_mpi(tmp2, tmp3, grp->prime);	//tmp2=tmp3 mod prime

		if (sae_debug_mask & SAE_DEBUG_MBED) {
			sae_debug(SAE_DEBUG_MBED, " tmp2 = tmp2 * tmp1 \n");
			pp_a_bignum("tmp2", tmp2);
		}

		mbedtls_mpi_mul_mpi(tmp3, tmp2, tmp1);	//tmp3=tmp2 * tmp1
		mbedtls_mpi_mod_mpi(tmp2, tmp3, grp->prime);	//tmp2=tmp3 mod prime

		if (sae_debug_mask & SAE_DEBUG_MBED) {
			sae_debug(SAE_DEBUG_MBED, " tmp2 = tmp2 * tmp1 \n");
			pp_a_bignum("tmp2", tmp2);
		}

		/*
		 * now tmp2 (y^2) is masked, all values between 1 and p-1
		 * are equally probable. Multiplying by r^2 does not change
		 * whether or not tmp2 is a quadratic residue, just masks it.
		 *
		 * flip a coin, multiply by the random quadratic residue or the
		 * random quadratic nonresidue and record heads or tails
		 */
		sae_debug(SAE_DEBUG_MBED, " multiply by the qr or qnr\n");
		if (tmp_is_odd(tmp1)) {
			sae_debug(SAE_DEBUG_MBED, " tmp1 is odd \n");
			mbedtls_mpi_mul_mpi(tmp3, tmp2, qr);	//tmp3 = tmp2 * qr
			//mbedtls_mpi_mod_mpi(tmp2, tmp3, grp->prime);//tmp2=tmp3 mod prime
			mbedtls_mpi_mod_mpi(tmp2, tmp3, &grp->group->P);	//tmp2=tmp3 mod prime

			if (sae_debug_mask & SAE_DEBUG_MBED) {
				sae_debug(SAE_DEBUG_MBED, " tmp2 = tmp2 * qr \n");
				pp_a_bignum("tmp2", tmp2);
			}
			check = 1;
		} else {
			sae_debug(SAE_DEBUG_MBED, " tmp1 is not odd \n");
			mbedtls_mpi_mul_mpi(tmp3, tmp2, qnr);	//tmp3=tmp2 * qnr
			mbedtls_mpi_mod_mpi(tmp2, tmp3, &grp->group->P);	//tmp2=tmp3 mod prime
			//mbedtls_mpi_mod_mpi(tmp2, tmp3, grp->prime);//tmp2=tmp3 mod prime

			if (sae_debug_mask & SAE_DEBUG_MBED) {
				sae_debug(SAE_DEBUG_MBED, " tmp2 = tmp2 * qnr \n");
				pp_a_bignum("tmp2", tmp2);
			}
			check = -1;
		}

		/*
		 * now it's safe to do legendre, if check is 1 then it's
		 * a straightforward test (multiplying by qr does not
		 * change result), if check is -1 then its the opposite test
		 * (multiplying a qr by qnr would make a qnr)
		 */
		sae_debug(SAE_DEBUG_MBED, " doing legendre\n");
		if (legendre(tmp2, grp->prime, pm1d2) == check) {
			if (found == 1) {
				continue;
			}
			/*
			 * need to unambiguously identify the solution, if there is one...
			 */
			/*   if (rnd->s != y->s)
			   {
			   is_odd = 1;
			   sae_debug(SAE_DEBUG_MBED, "is_odd = 1;\n");
			   }
			   else
			   {
			   is_odd = 0;
			   sae_debug(SAE_DEBUG_MBED, "is_odd = 0;\n");
			   }
			 */
			x = (mbedtls_mpi *) kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
			if (x == NULL) {
				sae_debug(SAE_DEBUG_ERR, "can't create bignum for candidate!\n");
				goto assign_group_to_peer_fail;
			}
			mbedtls_mpi_init(x);

			y = (mbedtls_mpi *) kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
			if (y == NULL) {
				sae_debug(SAE_DEBUG_ERR, "can't create bignum for candidate!\n");
				goto assign_group_to_peer_fail;
			}
			mbedtls_mpi_init(y);

			mbedtls_mpi_copy(x, x_candidate);
			mbedtls_mpi_copy(y, y_candidate);
			if (sae_debug_mask & SAE_DEBUG_MBED) {
				sae_debug(SAE_DEBUG_MBED, "copy x_candidate to x\n");
				pp_a_bignum("x", x);
				pp_a_bignum("x_candidate", x_candidate);
				pp_a_bignum("y", y);
				pp_a_bignum("y_candidate", y_candidate);
			}
			sae_debug(SAE_DEBUG_CRYPTO, "it took %d tries to find PWE: %d\n", ctr, grp->group_num);
			found = 1;
			break;
		}
	}
	/*
	 * 2^-40 is about one in a trillion so we should always find a point.
	 * When we do, we know x^3 + ax + b is a quadratic residue so we can
	 * assign a point using x and our discriminator (is_odd)
	 */
	if ((found == 0) || (tmp_set_compressed_coordinates_GFp(grp->prime, peer->pwe, x, y, rnd) == -1)) {
		mbedtls_ecp_point_free(peer->pwe);
		peer->pwe = NULL;
	}
	if (sae_debug_mask & SAE_DEBUG_CRYPTO_VERB) {
		mbedtls_mpi *px = NULL, *py = NULL;
		px = &peer->pwe->X;
		py = &peer->pwe->Y;

		log("PWE (x,y):\n");
		memset(prfbuf, 0, mbedtls_mpi_size(grp->prime));
		mbedtls_mpi_write_binary(px, prfbuf + (mbedtls_mpi_size(grp->prime) - mbedtls_mpi_size(px)),
					 mbedtls_mpi_size(px));
		print_buffer("x", prfbuf, mbedtls_mpi_size(grp->prime));
		memset(prfbuf, 0, mbedtls_mpi_size(grp->prime));
		mbedtls_mpi_write_binary(py, prfbuf + (mbedtls_mpi_size(grp->prime) - mbedtls_mpi_size(py)),
					 mbedtls_mpi_size(py));
		print_buffer("y", prfbuf, mbedtls_mpi_size(grp->prime));
	}

assign_group_to_peer_fail:

	//free buffer
	if (prfbuf) {
		kfree(prfbuf);
		prfbuf = NULL;
	}
	if (primebuf) {
		kfree(primebuf);
		primebuf = NULL;
	}
	//Free mbedtls_mpi
	if (a) {
		mbedtls_mpi_free(a);
		kfree(a);
		a = NULL;
	}
	if (rnd) {
		mbedtls_mpi_free(rnd);
		kfree(rnd);
		rnd = NULL;
	}
	if (pm1d2) {
		mbedtls_mpi_free(pm1d2);
		kfree(pm1d2);
		pm1d2 = NULL;
	}
	if (pm1) {
		mbedtls_mpi_free(pm1);
		kfree(pm1);
		pm1 = NULL;
	}
	if (tmp1) {
		mbedtls_mpi_free(tmp1);
		kfree(tmp1);
		tmp1 = NULL;
	}
	if (tmp2) {
		mbedtls_mpi_free(tmp2);
		kfree(tmp2);
		tmp2 = NULL;
	}
	if (tmp3) {
		mbedtls_mpi_free(tmp3);
		kfree(tmp3);
		tmp3 = NULL;
	}
	if (qr) {
		mbedtls_mpi_free(qr);
		kfree(qr);
		qr = NULL;
	}
	if (qnr) {
		mbedtls_mpi_free(qnr);
		kfree(qnr);
		qnr = NULL;
	}
	if (x_candidate) {
		mbedtls_mpi_free(x_candidate);
		kfree(x_candidate);
		x_candidate = NULL;
	}
	if (y_candidate) {
		mbedtls_mpi_free(y_candidate);
		kfree(y_candidate);
		y_candidate = NULL;
	}
	if (x) {
		mbedtls_mpi_free(x);
		kfree(x);
		x = NULL;
	}
	if (y) {
		mbedtls_mpi_free(y);
		kfree(y);
		y = NULL;
	}
	if ((peer->pwe == NULL) || (peer->pwe->X.p == NULL) || (peer->pwe->Y.p == NULL)) {
		sae_debug(SAE_DEBUG_ERR, "unable to find random point on curve for group %d, something's fishy!\n",
			  grp->group_num);
		if (peer->pwe) {
			mbedtls_ecp_point_free(peer->pwe);
			kfree(peer->pwe);
			peer->pwe = NULL;
		}
		if (peer->peer_element) {
			mbedtls_ecp_point_free(peer->peer_element);
			kfree(peer->peer_element);
			peer->peer_element = NULL;
		}
		if (peer->my_element) {
			mbedtls_ecp_point_free(peer->my_element);
			kfree(peer->my_element);
			peer->my_element = NULL;
		}
		return -1;
	}
	sae_debug(SAE_DEBUG_PROTOCOL_MSG, "assigning group %d to peer, the size of the prime is %d\n",
		  peer->grp_def->group_num, mbedtls_mpi_size(peer->grp_def->prime));

	return 0;
}

void retransmit_peer(struct rtl8192cd_priv *priv, struct candidate *peer)
{
	sae_debug(SAE_DEBUG_STATE_MACHINE, "timer %d fired! retrans = %d, incrementing\n", peer->t0, peer->sync);
	if (peer->sync > priv->giveup_threshold) {
		sae_debug(SAE_DEBUG_STATE_MACHINE, "peer not listening!\n");
		if (peer->state == SAE_COMMITTED) {
			/*
			 * if the peer never responded then put it on the blacklist for a while
			 */
			sae_debug(SAE_DEBUG_STATE_MACHINE, MACSTR " never responded, adding to blacklist\n",
				  MAC2STR(peer->peer_mac));
			blacklist_peer(priv, peer);
		}
		fin(priv, WLAN_STATUS_AUTHENTICATION_TIMEOUT, peer->peer_mac, NULL, 0);
		delete_peer(priv, peer->peer_mac);
		return;
	}
	peer->sync++;
	switch (peer->state) {
	case SAE_COMMITTED:
		commit_to_peer(priv, peer->peer_mac, NULL, 0);
		peer->t0 = jiffies;
		break;
	case SAE_CONFIRMED:
		confirm_to_peer(priv, peer->peer_mac);
		peer->t0 = jiffies;
		break;
	default:
		sae_debug(SAE_DEBUG_STATE_MACHINE, "timer fired and not committed or confirmed!\n");
		break;
	}
}

static int next_candidate_id = 0;

struct candidate *create_candidate(struct rtl8192cd_priv *priv, unsigned char *her_mac, unsigned char *my_mac,
				   unsigned short got_token)
{
	struct candidate *peer = NULL, *peer_temp = NULL;

	if ((peer = kmalloc(sizeof(struct candidate), GFP_ATOMIC)) == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't malloc space for candidate!\n");
		return NULL;
	}
	memset(peer, 0, sizeof(struct candidate));
	memcpy(peer->my_mac, my_mac, ETH_ALEN);
	memcpy(peer->peer_mac, her_mac, ETH_ALEN);

	peer->peer_scalar = kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (peer->peer_scalar == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't create peer data structures!\n");
		return NULL;
	}
	mbedtls_mpi_init(peer->peer_scalar);

	peer->my_scalar = kmalloc(sizeof(mbedtls_mpi), GFP_ATOMIC);
	if (peer->my_scalar == NULL) {
		sae_debug(SAE_DEBUG_ERR, "can't create peer data structures!\n");
		kfree(peer->peer_scalar);
		return NULL;
	}
	mbedtls_mpi_init(peer->my_scalar);
	HASH_INSERT(GET_ROOT(priv)->sae_peer_table, peer->peer_mac, peer);
	kfree(peer);
	peer = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, her_mac);
	peer->got_token = got_token;
	peer->failed_auth = peer->beacons = peer->state = peer->sync = peer->sc = peer->rc = 0;
	peer->private_val = NULL;
	peer->pwe = peer->peer_element = peer->my_element = NULL;
	peer->state = SAE_NOTHING;
	//peer->cookie = cookie;
	peer->candidate_id = next_candidate_id++;
	priv->curr_open++;

	//log("peer_created at address %x", peer);
	return peer;
}

// This is used to verify that the invariants for candidate peers are preserved,
// namely that there are no more than two candidates for a peer and if there are
// two candidates then one is accepted and one is not.
static int validate_peers(struct rtl8192cd_priv *priv, unsigned char *mac)
{
	/*
	   const int MaxPeers = 10;
	   struct candidate *peer;
	   struct candidate *candidates[MaxPeers];
	   int i, count = 0;

	   peer = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, mac);
	   if (peer)
	   {
	   if (count < MaxPeers)               // pointless to report problems with candidates after MaxPeers
	   candidates[count++] = peer;
	   }

	   if (count > 2)
	   {
	   sae_debug(SAE_DEBUG_STATE_MACHINE, "found %d candidates for peer %pm!!!\n", count, mac);
	   for (i = 0; i < count; ++i)
	   peer = candidates[i];
	   }
	   else if (count == 2)
	   {
	   if ((candidates[0]->state == SAE_ACCEPTED && candidates[1]->state == SAE_ACCEPTED) ||
	   (candidates[0]->state != SAE_ACCEPTED && candidates[1]->state != SAE_ACCEPTED))
	   sae_debug(SAE_DEBUG_STATE_MACHINE, "peer %pm should have one and only one accepted candidate!!!\n", mac);
	   }
	 */
	struct candidate *peer;

	return ((peer = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, mac)) == NULL);
}

static bool reauth_in_progress(struct candidate *peer)
{
	if (peer->state == SAE_COMMITTED || peer->state == SAE_CONFIRMED)
		return true;

	else if (peer->link_state == PLINK_OPN_SNT ||
		 peer->link_state == PLINK_OPN_RCVD || peer->link_state == PLINK_CNF_RCVD)
		return true;

	return false;
}

void do_reauth(struct rtl8192cd_priv *priv, struct candidate *peer)
{
	struct candidate *newpeer = NULL;

	int count = ((peer == NULL) ? 0 : 1);	//validate_peers(peer->peer_mac);

	if (!reauth_in_progress(peer) && count == 1) {
		if ((newpeer = create_candidate(priv, peer->peer_mac, peer->my_mac, 0)) != NULL) {
			if (assign_group_to_peer(priv, priv->gd, newpeer->peer_mac) < 0) {
				delete_peer(priv, newpeer->peer_mac);
			} else {
				commit_to_peer(priv, newpeer->peer_mac, NULL, 0);
				newpeer->t0 = jiffies;
				newpeer->state = SAE_COMMITTED;
			}
		}
		/*
		 * make a hard deletion of this guy in case the reauth fails and we
		 * don't end up deleting this instance
		 */
		peer->t2 = DESTORY_PEER;

	} else {
		//if (peer->t1)
		//    srv_rem_timeout(srvctx, peer->t1);
		peer->t1 = jiffies;
	}
}

/*
void
reauth ((struct candidate *)data)
{
    struct candidate *peer = (struct candidate *)data;
    do_reauth(peer);
}
*/

static enum result
//process_authentication_frame(struct rtl8192cd_priv *priv, struct ieee80211_mgmt_frame *frame, int len)
sae_process_auth(struct rtl8192cd_priv *priv, struct ieee80211_mgmt_frame *frame, int framelen)
{
	unsigned short grp;
	unsigned short seq = ieee_order(frame->authenticate.auth_seq);
	unsigned short status = ieee_order(frame->authenticate.status);
	GD *group_def = NULL;
	struct candidate *delme = NULL;
	enum result ret;
	struct candidate *peer = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, frame->sa);
#ifndef SMP_SYNC
	unsigned long flags;
#endif
	unsigned char resp_buf[256];
	unsigned char resp_buf_len=0;
	memset(resp_buf,0,256);

	log("peer[%pm] seq[%s] state[%s]", frame->sa, seq_to_string(seq), state_to_string(peer->state));

	//srv_rem_timeout(srvctx, peer->t0);
	peer->t0 = 0;
	/*
	 * implement the state machine for SAE
	 */
	switch (peer->state) {
	case SAE_NOTHING:
		switch (seq) {
		case SAE_AUTH_COMMIT:
			/*
			 * if the status is anything other than 0 then throw this away
			 * since as far as we're concerned this is unsolicited and there's
			 * no error we committed.
			 */
			if (status != 0) {
				return ERR_FATAL;
			}
			/*
			 * grab the group from the frame...
			 */
			grp = ieee_order(*((frame->authenticate.u.var16)));
			log("peer's group id=[%d]",grp);
			/*
			 * ...and see if it's supported
			 */
			group_def = priv->gd;
			while (group_def) {
				if (grp == group_def->group_num) {
					log("assign_group_to_peer[%d]",group_def->group_num);
					if (assign_group_to_peer(priv, group_def, frame->sa) < 0) {
						return ERR_FATAL;
					}
					break;
				}
				group_def = group_def->next;
			}
			if (group_def == NULL) {
				/*
				 * send a rejection to the peer and a "del" event to the parent
				 */
				log("group %d not supported, reject.\n", grp);
				reject_to_peer(priv, peer, frame);
				return ERR_FATAL;
			}

			log("[COMMIT] from unknown peer [%pm],committing and confirming", peer->peer_mac);

			peer->sc = peer->rc = 0;

			prepare_commit_to_peer(priv, frame->sa, NULL, 0, &resp_buf, &resp_buf_len);
			//log("going to process commit");
			if (process_commit(priv, frame, framelen) < 0) {
				log("COMMIT-ELEMENT error, reject.\n");
				reject_to_peer(priv, peer, frame);
				return ERR_FATAL;
			}
			log("send_commit_to_peer,len[%d]",resp_buf_len);
			send_commit_to_peer(priv, frame->sa, resp_buf, resp_buf_len);

			/*
			 * send both a commit and a confirm and transition into confirmed
			 */

			//log("going to comfirm\n");
			confirm_to_peer(priv, frame->sa);
			peer->sync = 0;
			peer->t0 = jiffies;
			SAVE_INT_AND_CLI(flags);
			peer->state = SAE_CONFIRMED;
			report_event_sae(priv, peer, NULL, REPORT_SAE_CONFIRMED);	//rtk_sae
			RESTORE_INT(flags);

			break;
		case SAE_AUTH_CONFIRM:
			return ERR_FATAL;
		default:
			log("unknown SAE frame (%d) from %pm\n", seq, peer->peer_mac);
			return ERR_NOT_FATAL;
		}
		break;
	case SAE_COMMITTED:
		switch (seq) {
		case SAE_AUTH_COMMIT:
			/*
			 * if it's an anti-clogging token request, send another
			 * commit with the token.
			 *
			 * Increment the sync counter, the spec doesn't say so but this
			 * guards against bad implementations.
			 rx token req & resend commit
			 */
			if (status == WLAN_STATUS_ANTI_CLOGGING_TOKEN_NEEDED){
				/*!!!NOTICE  here is a length check for AUTH_SAE_STA has been modified*/
				log("total len[%d] len2[%d]", framelen, sizeof(frame->authenticate));
				log("RX token request,add token,len:%d, and resend commit", (framelen - (IEEE802_11_HDR_LEN + 8)));

				commit_to_peer(priv, frame->sa, frame->authenticate.u.var8 + 2,(framelen - (IEEE802_11_HDR_LEN + 8)));
				peer->sync = 0;
				peer->t0 = jiffies;
				break;
			}
			/*
			 * grab the group from the frame, we need it later
			 */
			grp = ieee_order(*((frame->authenticate.u.var16)));

			if (status == WLAN_STATUS_NOT_SUPPORTED_GROUP) {
				/*
				 * if it's a rejection check whether it's what we sent.
				 * If so try another configured group.
				 */
				if (grp == peer->grp_def->group_num) {
					/*
					 * if there's no more configured groups to offer then just declare failure,
					 * blacklist the client since we cannot currently communicate.
					 */
					if (peer->grp_def->next == NULL) {
						log("ERR_BLACKLIST");
						return ERR_BLACKLIST;
					}
					/*
					 * otherwise assign the next group and send another commit
					 */
					group_def = peer->grp_def->next;
					log("peer rejected %d, try group %d instead...\n",
					    peer->grp_def->group_num, group_def->group_num);
					assign_group_to_peer(priv, group_def, frame->sa);
					commit_to_peer(priv, frame->sa, NULL, 0);
					peer->sync = 0;
				} else {
					log("peer is rejecting something (%d) not offered, must be old, ignore...\n",
					    grp);
				}
				peer->t0 = jiffies;
				break;
			}
			/*
			 * silently drop any other failure
			 */
			if (status != 0) {
				peer->t0 = jiffies;
				break;
			}
			/*
			 * if the group offered is not the same as what we offered
			 * that means the commit messages crossed in the ether. Check
			 * whether this is something we can support and if so tie break.
			 */
			if (grp != peer->grp_def->group_num) {
				group_def = priv->gd;
				while (group_def) {
					if (grp == group_def->group_num) {
						break;
					}
					group_def = group_def->next;
				}
				/*
				 * nope, not supported, send rejection
				 */
				if (group_def == NULL) {
					if (peer->sync > priv->giveup_threshold) {
						return ERR_FATAL;
					}
					log("group %d not supported, send rejection\n", grp);
					peer->sync++;
					reject_to_peer(priv, peer, frame);
					peer->t0 = jiffies;
					break;
				}
				/*
				 * OK, this is not what we offered but it's aceptable...
				 */
				if (memcmp(peer->my_mac, peer->peer_mac, ETH_ALEN) > 0) {
					log("offered group %d, got %d in return, numerically greater, maintain.\n",
					    peer->grp_def->group_num, grp);

					/*
					 * the numerically greater MAC address retransmits
					 */
					commit_to_peer(priv, frame->sa, NULL, 0);
					peer->t0 = jiffies;
					break;
				} else {
					log("offered group %d, got %d in return, numerically lesser, submit.\n",
					    peer->grp_def->group_num, grp);
					/*
					 * the numerically lesser converts, send a commit with
					 * this group and then just proceed with the acceptable
					 * commit
					 */
					peer->sync = 0;

					log("assign_group_to_peer[%d]\n\n",group_def->group_num);
					assign_group_to_peer(priv, group_def, frame->sa);
					commit_to_peer(priv, frame->sa, NULL, 0);
					log("going to process commit");
					if (process_commit(priv, frame, framelen) < 0) {
						return ERR_FATAL;
					}
				}
			} else {
				/*
				 * else it's the group we offered, check for a reflection attack,
				 * and if not then process the frame
				 */
				/*check for reflection attack [5.2.3]*/
				if (check_dup(priv, 1, frame, framelen) == 0) {
					log("detect reflection attack");
					/*[RTK]deny this peer for a while*/
					return ERR_BLACKLIST;
					/* silently discard */
					//return NO_ERR;
				}
				log("going to process commit");
				if (process_commit(priv, frame, framelen) < 0) {
					return ERR_FATAL;
				}
			}
			confirm_to_peer(priv, frame->sa);
			peer->t0 = jiffies;
			SAVE_INT_AND_CLI(flags);
			peer->state = SAE_CONFIRMED;

			report_event_sae(priv, peer, NULL, REPORT_SAE_CONFIRMED);	//rtk_sae

			RESTORE_INT(flags);
			break;
		case SAE_AUTH_CONFIRM:
			log("got CONFIRM before COMMIT, try again\n");
			if (peer->sync > priv->giveup_threshold) {
				return ERR_FATAL;
			}
			peer->sync++;
			commit_to_peer(priv, frame->sa, NULL, 0);
			peer->t0 = jiffies;
			break;
		default:
			log("unknown SAE frame (%d) from %pm\n", seq, peer->peer_mac);
			return ERR_NOT_FATAL;
		}
		break;
	case SAE_CONFIRMED:
		if (status != 0) {
			/*
			 * silently discard, but since we cancelled the timer above, reset it
			 */
			peer->t0 = jiffies;
			break;
		}
		switch (seq) {
		case SAE_AUTH_COMMIT:
			if (peer->sync > priv->giveup_threshold) {
				return ERR_FATAL;
			}

			grp = ieee_order(*(u16 *) ((unsigned char *)frame + WLAN_HDR_A3_LEN + _AUTH_IE_OFFSET_));
			if (grp == peer->grp_def->group_num) {
				log("got COMMIT again, try to resync\n");
				peer->sync++;
				log("COMMITing\n");
				commit_to_peer(priv, frame->sa, NULL, 0);
				log("CONFIRMing\n");
				confirm_to_peer(priv, frame->sa);
			}
			peer->t0 = jiffies;
			break;
		case SAE_AUTH_CONFIRM:
			ret = process_confirm(peer, frame, framelen);
			switch (ret) {
			case ERR_FATAL:
			case ERR_BLACKLIST:
				log("Delete event received from protocol instance for %pm\n", peer->peer_mac);
				return ret;
			case ERR_NOT_FATAL:	/* this is not in 11s draft */
				peer->sync++;
				confirm_to_peer(priv, frame->sa);
				return NO_ERR;
			case NO_ERR:
				break;
			}
			priv->curr_open--;
			peer->sc = COUNTER_INFINITY;
			if (((delme = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, peer->peer_mac)) != NULL)
			    && (delme->state == SAE_ACCEPTED)) {
				log("peer %pm in %s has just ACCEPTED, found another in %s, deleting\n", peer->peer_mac,
				    state_to_string(peer->state), state_to_string(delme->state));
				SAVE_INT_AND_CLI(flags);
				delete_peer(priv, peer->peer_mac);
				RESTORE_INT(flags);
			}
			/*
			 * print out the PMK if we have debugging on for that
			 */
			if (peer->state != SAE_ACCEPTED) {
				if (sae_debug_mask & SAE_DEBUG_CRYPTO) {
					print_buffer("PMK", peer->pmk, MBEDTLS_DIGEST_LENGTH);
				}
				fin(priv, WLAN_STATUS_SUCCESSFUL, peer->peer_mac, peer->pmk, MBEDTLS_DIGEST_LENGTH);
			}
			log("setting pmk_expiry timer for %d seconds", priv->pmk_expiry);
			//if (peer->t1)
			//     srv_rem_timeout(srvctx, peer->t1);
			peer->t1 = jiffies;
			SAVE_INT_AND_CLI(flags);
			peer->state = SAE_ACCEPTED;
			RESTORE_INT(flags);
			break;
		default:
			log("unknown SAE frame (%d) from %pm\n", seq, peer->peer_mac);
			return ERR_NOT_FATAL;
		}
		break;
	case SAE_ACCEPTED:
		switch (seq) {
		case SAE_AUTH_COMMIT:
			/*
			 * something stinks in state machine land...
			 */
			break;
		case SAE_AUTH_CONFIRM:
			if (peer->sync > priv->giveup_threshold) {
				log("too many syncronization errors on %pm, deleting\n", peer->peer_mac);
				return ERR_FATAL;
			}
			/*
			 * must've lost our confirm, check if it's old or invalid,
			 * if neither send confirm again....
			 */
			if (check_confirm(peer, frame) && (process_confirm(peer, frame, framelen) >= 0)) {
				log("peer %pm resending CONFIRM...\n", peer->peer_mac);
				peer->sync++;
				confirm_to_peer(priv, frame->sa);
			}
			break;
		default:
			log("unknown SAE frame (%d) from %pm\n", seq, peer->peer_mac);
			return ERR_NOT_FATAL;
		}
		break;
	}
	log("State of [%pm] is now (%d) %s", peer->peer_mac, peer->state, state_to_string(peer->state));
	return NO_ERR;
}

static int have_token(struct rtl8192cd_priv *priv, struct ieee80211_mgmt_frame *frame, int len, unsigned char *me)
{
	unsigned short seq = ieee_order(frame->authenticate.auth_seq);
	unsigned short alg;
	unsigned char *token = NULL;
	mbedtls_md_context_t ctx;
	GD *group_def = NULL;

	if ((token = kmalloc(MBEDTLS_DIGEST_LENGTH, GFP_ATOMIC)) == NULL) {
		log("token malloc fail\r\n");
		return -1;
	}
	memset(token, 0, MBEDTLS_DIGEST_LENGTH);

	/*
	 * if it's not a commit then by definition there's no token: bad
	 */
	if (seq != SAE_AUTH_COMMIT) {
		log("checking for token but not a commit!\n");
		kfree(token);
		return -1;
	}

	/*
	 * it's a commmit so the first thing is the finite cyclic group
	 */
	alg = ieee_order(*(frame->authenticate.u.var16));

	group_def = priv->gd;
	while (group_def) {
		if (alg == group_def->group_num) {
			break;
		}
		group_def = group_def->next;
	}
	if (group_def == NULL) {
		/*
		 * if the group isn't supported then there's no way we can truely
		 * evaluate this frame, just check whether our token is there. If the
		 * group isn't supported then at least we'll tell the peer of that fact
		 * later and maybe we can come to some resolution after a few more exchanges.
		 */
		if (len <
		    (IEEE802_11_HDR_LEN + sizeof(frame->authenticate) + sizeof(unsigned short) +
		     MBEDTLS_DIGEST_LENGTH)) {
			log("checking for token but there can't be one, too short!\n");
			/*
			 * no token, ask for one
			 */
			kfree(token);
			return 1;
		}
		//H_Init(&ctx, (unsigned char *)&priv->token_generator, sizeof(unsigned long));
		mbedtls_md_init(&ctx);
		mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
		//mbedtls_md_starts(&ctx);
		mbedtls_md_hmac_starts(&ctx, (unsigned char *)&priv->token_generator, sizeof(unsigned long));
		mbedtls_md_hmac_update(&ctx, frame->sa, ETH_ALEN);
		mbedtls_md_hmac_update(&ctx, me, ETH_ALEN);
		mbedtls_md_hmac_finish(&ctx, token);

		log("Calling mbedtls_md_hmac_finish for %pm\n", frame->sa);
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			print_buffer("token", token, MBEDTLS_DIGEST_LENGTH);
		}
		mbedtls_md_free(&ctx);
		if (memcmp(token, (frame->authenticate.u.var8 + sizeof(unsigned short)), MBEDTLS_DIGEST_LENGTH)) {
			/*
			 * there's something there but it's not a token, so ask for one.
			 *
			 * should we maybe return -1 to silently drop this frame? Hmmm...
			 */
			return 1;
		}
	} else {
		/*
		 * The length should be the size of an authenticate frame (minus all the optional
		 * fields and IEs) plus the size of the finite cyclic group field (unsigned short)
		 * plus the size of the tokens we generate (SHA256_DIGEST_LEN) plus the size of
		 * the order of the selected group plus twice the size of the prime of the selected
		 * group (x-coordinate and y-coordinate, each the length of the prime).
		 *
		 * NB: if/when FFC groups are supported it won't be plus twice the prime, it'll just be
		 * plus the length of the prime (an FFC element is not complex like an ECC element is).
		 */
		if (len != (IEEE802_11_HDR_LEN + sizeof(frame->authenticate) + sizeof(unsigned short) +
			    MBEDTLS_DIGEST_LENGTH + mbedtls_mpi_size(group_def->order) +
			    (2 * mbedtls_mpi_size(group_def->prime)))) {
			sae_debug(SAE_DEBUG_PROTOCOL_MSG,
				  "checking for token in offer of group %d but length is wrong: %d vs. %d\n",
				  group_def->group_num, len,
				  (IEEE802_11_HDR_LEN + sizeof(frame->authenticate) + sizeof(unsigned short) +
				   MBEDTLS_DIGEST_LENGTH + mbedtls_mpi_size(group_def->order) +
				   (2 * mbedtls_mpi_size(group_def->prime))));
			kfree(token);
			return 1;
		}
		mbedtls_md_init(&ctx);
		mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
		mbedtls_md_hmac_starts(&ctx, (unsigned char *)&priv->token_generator, sizeof(unsigned long));
		mbedtls_md_hmac_update(&ctx, frame->sa, ETH_ALEN);
		mbedtls_md_hmac_update(&ctx, me, ETH_ALEN);
		mbedtls_md_hmac_finish(&ctx, token);

		sae_debug(SAE_DEBUG_MBED, "Calling mbedtls_md_hmac_finish\n");
		if (sae_debug_mask & SAE_DEBUG_MBED) {
			print_buffer("token", token, MBEDTLS_DIGEST_LENGTH);
		}
		mbedtls_md_free(&ctx);
		if (memcmp(token, (frame->authenticate.u.var8 + sizeof(unsigned short)), MBEDTLS_DIGEST_LENGTH)) {
			/*
			 * bad token
			 */
			kfree(token);
			return -1;
		}
	}
	/*
	 * found a token and it's good
	 */
	kfree(token);
	return 0;
}

/*
 * the "parent process" gets management frames as input and dispatches to
 * "protocol instances".
 */
static int compute_group_definition(
	struct rtl8192cd_priv *priv,
	GD * grp, unsigned char *password, unsigned short num)
{
	int nid;
	unsigned char key[65];
	memset(key,'\0',65);

	switch (num) {		/* from IANA registry for IKE D-H groups */
	case 19:
		nid = MBEDTLS_ECP_DP_SECP256R1;
		break;
	case 20:
		nid = MBEDTLS_ECP_DP_SECP384R1;
		break;
	case 21:
		nid = MBEDTLS_ECP_DP_SECP521R1;
		break;
	case 25:
		nid = MBEDTLS_ECP_DP_SECP192R1;
		break;
	case 26:
		nid = MBEDTLS_ECP_DP_SECP224R1;
		break;
	default:
		sae_debug(SAE_DEBUG_ERR, "unsupported group %d\n", num);
		return -1;
	}


	if (grp->group == NULL) {
		grp->group = kmalloc(sizeof(mbedtls_ecp_group), GFP_ATOMIC);
		if (grp->group == NULL) {
			sae_debug(SAE_DEBUG_ERR, "can't create grp->group!\n");
			return -1;
		}
	}
	mbedtls_ecp_group_init(grp->group);

	if (mbedtls_ecp_group_load(grp->group, nid) != 0) {
		sae_debug(SAE_DEBUG_ERR, "unable to create EC_GROUP!\n");
		kfree(grp->group);
		return -1;
	}
	grp->order = NULL;
	grp->prime = NULL;

	grp->prime = &grp->group->P;
	grp->order = &grp->group->N;

	if (sae_debug_mask & SAE_DEBUG_MBED) {
		pp_a_bignum("grp->prime", grp->prime);
		pp_a_bignum("grp->order", grp->order);
	}

	grp->group_num = num;

	if (strlen(password) == 64 && priv->pmib->wscEntry.wsc_enable==3) {	/*format is hex , need do str to hex*/
		log("len==64&& wsc_enable==3");
		get_array_val(key, password, 64);
		memcpy(grp->password, key, 32);
	}else{
		strncpy(grp->password, password, strlen(password));

	}

	dump_hex("sae psk", grp->password, strlen(grp->password));
	return 0;
}

void sae_dump_db(int unused)
{
	struct candidate *peer;
	return;
	/* fprintf(stderr, "SAE:\n");
	   TAILQ_FOREACH(peer, &peers, entry) {
	   fprintf(stderr, "\t%pM in state %s\n", MAC2STR(peer->peer_mac), state_to_string(peer->state));
	   } */
}

int sae_initialize(struct rtl8192cd_priv *priv)
{
	GD *curr = NULL;
	int i;

#ifdef	CONFIG_RTK_MESH
	priv->mesh_profile[0].AuthenticationProtocol = 1;
#endif

	/*
	 * initialize globals
	 */
	memset(priv->allzero, 0, MBEDTLS_DIGEST_LENGTH);

	mbedtls_platform_set_calloc_free(calloc, free);
#if 0
JC:
	Commented out until we decide whether this is needed(in which case we must
							     be prepared to accept a binary,
							     non -
							     null terminated mesh ID) or not(the mesh_ssid is not used
											     anywhere in this module,
											     so maybe it can be
											     dumped).memcpy(mesh_ssid,
													    ourssid,
													    strlen
													    (ourssid));
#endif
	//TAILQ_INIT(&peers);
	//TAILQ_INIT(&blacklist);
#if 1
	rand_bytes((unsigned char *)&priv->token_generator, sizeof(unsigned long));
#else
	memcpy(&priv->token_generator, TOKEN_COPY, 4);
#endif
	print_buffer("token_generator", (unsigned char *)&priv->token_generator, sizeof(unsigned long));

	priv->curr_open = 0;
	priv->open_threshold = priv->pmib->dot1180211AuthEntry.dot11SAETokenThres;	//rtk_sae OPEN_THRESHOLD;
	log("sae token threshold=[%d]", priv->open_threshold);
	//blacklist_timeout = BLACKLIST_TIMEOUT;
	priv->giveup_threshold = GIVEUP_THRESHOLD;
	//retrans = RETRANS;
	priv->pmk_expiry = PMK_EXPIRE;	/* one day */

	/*
	 * create groups from configuration data
	 */
	if(priv->gd==NULL){
		log("create group definition!\n");
		if ((curr = kmalloc(sizeof(GD), GFP_ATOMIC)) == NULL) {
			log("cannot malloc group definition!\n");
			return -1;
		}
		curr->next = NULL;
		priv->gd = curr;
	}else{
		log("reuse group definition!\n");
		curr=priv->gd;
	}

	memset(curr, 0, sizeof(GD));

	if (compute_group_definition(priv,
			curr, priv->pmib->dot1180211AuthEntry.dot11PassPhrase,
		     priv->pmib->dot1180211AuthEntry.dot11SAEGroup)) {
		log("compute_group_definition fail!!\n\n");
	}
	dump_hex("grp->password",curr->password, strlen(curr->password));
	log("group %d is configured, prime is %d bytes", curr->group_num, mbedtls_mpi_size(curr->prime));

	return 1;
}

void sae_received_beacon(struct rtl8192cd_priv *priv, unsigned char *sa)
{
	/*
	 * This is actually not part of the parent state machine but handling
	 * it here makes the rest of the protocol instance state machine nicer.
	 *
	 * a new mesh point! auth_req transitions from state "NOTHING" to "COMMITTED"
	 */
	struct candidate *peer = NULL;
#ifndef SMP_SYNC
	unsigned long flags;
#endif

	if (on_blacklist(priv, sa) || (peer = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, sa)) != NULL)
		return;
	/*
	 * we're already dealing with this guy, ignore his beacons now
	 */
	log("received a beacon from %pm, Initiate event", sa);

	if ((peer = create_candidate(priv, sa, GET_MY_HWADDR, 0)) == NULL) {
		return -1;
	}
	//peer->cookie = cookie;
	/*
	 * assign the first group in the list as the one to try
	 */
	if (assign_group_to_peer(priv, priv->gd, sa) < 0) {
		log("WLAN_STATUS_UNSPECIFIED_FAILURE");
		fin(priv, WLAN_STATUS_UNSPECIFIED_FAILURE, peer->peer_mac, NULL, 0);
		SAVE_INT_AND_CLI(flags);
		delete_peer(priv, peer->peer_mac);
		RESTORE_INT(flags);

	} else {
		log("commit_to_peer..");
		commit_to_peer(priv, sa, NULL, 0);
		peer->t0 = jiffies;
		SAVE_INT_AND_CLI(flags);
		peer->state = SAE_COMMITTED;
		RESTORE_INT(flags);
		log("state of  %pm is now (%d) %s\n\n", peer->peer_mac, peer->state, state_to_string(peer->state));
	}

}

enum result sae_received_auth(struct rtl8192cd_priv *priv, unsigned int framelen, unsigned char *sae_frame)
{
	unsigned short frame_control, type, auth_alg;
	struct candidate *peer = NULL;
	int need_token;
	enum result ret = ERR_FATAL;
	/*auth_alg = ieee_order(frame->authenticate.alg);
	   if (auth_alg != SAE_AUTH_ALG) {
	   sae_debug(SAE_DEBUG_PROTOCOL_MSG,
	   "let kernel handle authenticate (%d) frame from %pm to %pm\n",
	   auth_alg, MAC2STR(frame->sa), MAC2STR(frame->da));
	   break;
	   } */
	struct ieee80211_mgmt_frame *frame = kmalloc(framelen, GFP_ATOMIC);
	//log("sae_received_auth frame=0x%x sae_frame=0x%x len=%d",frame, sae_frame, len);
	memcpy(frame, sae_frame, framelen);
	//dump_hex("sae frame", sae_frame, len);
	peer = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, frame->sa);
	if (peer != NULL) {
		log("peer[%pm] in[%d,%s],seq[%d]",
		    peer->peer_mac, peer->state, state_to_string(peer->state),
		    ieee_order(frame->authenticate.auth_seq));
	}
	switch (ieee_order(frame->authenticate.auth_seq)) {
	case SAE_AUTH_COMMIT:
		if ((peer != NULL) && (peer->state != SAE_ACCEPTED)) {
			ret = sae_process_auth(priv, frame, framelen);
			log("state of  %pm is now (%d) %s", peer->peer_mac, peer->state, state_to_string(peer->state));
		} else {
			/*
			 * check if this is the same scalar that was sent when we
			 * accepted.
			 */
			if ((peer != NULL) && (peer->state == SAE_ACCEPTED)) {
				if (check_dup(priv, 0, frame, framelen) == 0) {
					kfree(frame);
					return 0;
				}
			}
			/*
			 * if we are currently in a token-demanding state then check for a token
			 */
			log("clogging[%d] anti-clogging TH[%d]", priv->curr_open, priv->open_threshold);

			if (!(priv->curr_open < priv->open_threshold)) {
				need_token = have_token(priv, frame, framelen, GET_MY_HWADDR);

				log("need_token=[%d]", need_token);

				if (need_token < 0) {
					/*
					 * silently drop nonsense frames
					 */
					log("silently drop nonsense frames");
					kfree(frame);
					return 0;
				} else if (need_token > 0) {
					/*
					 * request a token if the frame should have one but didn't
					 */
					log("token needed for COMMIT (%d open), requesting one", priv->curr_open);
					request_token(priv, frame, GET_MY_HWADDR, peer);
					kfree(frame);
					return 0;
				} else {
					log("correct token received\n");
				}
			}
			/*
			 * if we got here that means we're not demanding tokens or we are
			 * and the token was correct. In either case we create a protocol instance.
			 */
			peer =
			    create_candidate(priv, frame->sa, GET_MY_HWADDR, (priv->curr_open >= priv->open_threshold));
			if (peer == NULL) {
				sae_debug(SAE_DEBUG_ERR, "create_candidate for peer[%pM] fail ", frame->sa);
				kfree(frame);
				return -1;
			}
			ret = sae_process_auth(priv, frame, framelen);
		}
		break;
	case SAE_AUTH_CONFIRM:
		if (peer == NULL) {
			log("fail! CHK!!");
			/*
			 * no peer instance, no way to handle this frame!
			 */
			kfree(frame);
			return 0;
		}
		/*
		 * since we searched above with "0" the peer we've handled the case
		 * of two peers in the db with one in ACCEPTED state already.
		 */
		ret = sae_process_auth(priv, frame, framelen);
		break;
	default:
		printk("We have a strange sae seq %x\n", ieee_order(frame->authenticate.alg));
		break;
	}

	switch (ret) {
	case ERR_BLACKLIST:
		/*
		 * a "del" event
		 */
		blacklist_peer(priv, peer);
		log("WLAN_STATUS_UNSPECIFIED_FAILURE");
		fin(priv, WLAN_STATUS_UNSPECIFIED_FAILURE, peer->peer_mac, NULL, 0);
		/* no break / fall-through intentional */
	case ERR_FATAL:
		/*
		 * a "fail" event, it could be argued that fin() should be done
		 * here but there are a certain class of failures-- group rejection
		 * for instance-- that don't really need fin() notification because
		 * the protocol might recover and successfully finish later.
		 */
		//
		delete_peer(priv, peer->peer_mac);
		kfree(frame);
		return 0;
	case ERR_NOT_FATAL:
		/*
		 * This isn't in the 11s draft but when there is some internal error from
		 * an API call it's not really a protocol error. These things can (should?)
		 * be handled with a "fail" event but let's try and be a little more accomodating.
		 *
		 * if we get a non-fatal error return to NOTHING but don't delete yet, this way we
		 * won't try to authenticate her again when we see a beacon but will respond to an
		 * initiation from her later.
		 */
		peer->failed_auth++;
		peer->sync = peer->sc = peer->rc = 0;
		peer->state = SAE_NOTHING;
		break;
	case NO_ERR:
		break;
	}

	if (peer->sync > priv->giveup_threshold) {
		/*
		 * if the state machines are so out-of-whack just declare failure
		 */
		log("too many state machine syncronization errors, adding %pm to blacklist\n", peer->peer_mac);
		blacklist_peer(priv, peer);
		fin(priv, WLAN_STATUS_REQUEST_DECLINED, peer->peer_mac, NULL, 0);
		delete_peer(priv, peer->peer_mac);
	}
	kfree(frame);
	return ret;
}

int issue_sae_frame(struct rtl8192cd_priv *priv, u8 * Entry, size_t len)
{
	u8 *pbuf;
	DECLARE_TXINSN(txinsn);
	txinsn.retry = priv->pmib->dot11OperationEntry.dot11ShortRetryLimit;
#ifdef	CONFIG_RTK_MESH
	txinsn.is_11s = GET_MIB(priv)->dot1180211sInfo.mesh_enable;
#endif
	txinsn.q_num = MANAGE_QUE_NUM;
	txinsn.fr_type = _PRE_ALLOCMEM_;
	txinsn.tx_rate = find_rate(priv, NULL, 0, 1);
#ifndef TX_LOWESTRATE
	txinsn.lowest_tx_rate = txinsn.tx_rate;
#endif
	txinsn.fixed_rate = 1;

	pbuf = txinsn.pframe = get_mgtbuf_from_poll(priv);

	if (pbuf == NULL)
		goto issue_sae_fail;

	txinsn.phdr = get_wlanhdr_from_poll(priv);

	if (txinsn.phdr == NULL)
		goto issue_sae_fail;

	memset((void *)(txinsn.phdr), 0, 24);
	memcpy((void *)(txinsn.phdr), (void *)(Entry), 24);
	memcpy((void *)(pbuf), (void *)(Entry + 24), len - 24);
	pbuf += len - 24;
	txinsn.fr_len += len - 24;

	if ((rtl8192cd_firetx(priv, &txinsn)) == SUCCESS) {
		/*successsfully */
		log("#sae-auth sent#");
		return 0;
	} else {
		sae_debug(SAE_DEBUG_ERR, "send frame to peer[%pm] fail", GetAddr3Ptr(txinsn.phdr));
	}

issue_sae_fail:
	if (txinsn.phdr)
		release_wlanhdr_to_poll(priv, txinsn.phdr);
	if (txinsn.pframe)
		release_mgtbuf_to_poll(priv, txinsn.pframe);
	return -1;
}

int sae_rand_range(mbedtls_mpi * output, mbedtls_mpi * range)
{
	size_t len;
	unsigned char *buf;

	if (mbedtls_mpi_cmp_int(range, 1) <= 0)
		return 0;
	len = mbedtls_mpi_size(range);
	if (len == 1)
		mbedtls_mpi_lset(output, 0);
	else {
		do {
			if ((buf = kmalloc(len, GFP_ATOMIC)) == NULL) {
				sae_debug(SAE_DEBUG_ERR, "sae_rand_range malloc fail\n");
				return 0;
			}
			get_random_bytes(buf, len);
			mbedtls_mpi_read_binary(output, buf, len);
		}
		while (mbedtls_mpi_cmp_mpi(output, range) >= 0);
	}
	kfree(buf);
	return 1;
}

void rand_bytes(unsigned char *pb, size_t cb)
{

	mbedtls_ctr_drbg_context ctx;

	mbedtls_ctr_drbg_init(&ctx);
	mbedtls_ctr_drbg_seed_entropy_len(&ctx, ctr_drbg_self_test_entropy, (void *)entropy_source_pr, nonce_pers_pr,
					  16, 32);
	mbedtls_ctr_drbg_random(&ctx, pb, cb);
	mbedtls_ctr_drbg_free(&ctx);
}

int sae_peer_table_expire(struct rtl8192cd_priv *priv)
{
	int tbl_sz = 1 << GET_ROOT(priv)->sae_peer_table->table_size_power;
	int i;
	unsigned long now = jiffies;
	unsigned long flags;
	struct candidate *peer_entry;

	for (i = 0; i < tbl_sz; i++) {
		SAVE_INT_AND_CLI(flags);
		if (GET_ROOT(priv)->sae_peer_table->entry_array[i].dirty) {
			peer_entry = ((struct candidate *)GET_ROOT(priv)->sae_peer_table->entry_array[i].data);
			if ((peer_entry->t0 != 0) && RTL_JIFFIES_TO_SECOND(now - peer_entry->t0) > RETRANS) {
				retransmit_peer(priv, peer_entry);
			}

			if ((peer_entry->t1 != 0) && RTL_JIFFIES_TO_SECOND(now - peer_entry->t1) > PMK_EXPIRE) {
				do_reauth(priv, peer_entry);
			}
		}
		RESTORE_INT(flags);
	}

	tbl_sz = 1 << GET_ROOT(priv)->sae_blacklist_table->table_size_power;
	now = jiffies;
	for (i = 0; i < tbl_sz; i++) {
		SAVE_INT_AND_CLI(flags);
		if (GET_ROOT(priv)->sae_blacklist_table->entry_array[i].dirty) {
			peer_entry = ((struct candidate *)GET_ROOT(priv)->sae_blacklist_table->entry_array[i].data);
			if ((peer_entry->black_list_time != 0)
			    && RTL_JIFFIES_TO_SECOND(now - peer_entry->black_list_time) > BLACKLIST_TIMEOUT) {
				remove_from_blacklist(priv, peer_entry->peer_mac);
			}
		}
		RESTORE_INT(flags);
	}

	return 0;
}

#ifdef AUTH_SAE_STA
int clean_up_sae_blacklist_table(struct rtl8192cd_priv *priv)
{

	int tbl_sz = 1 << GET_ROOT(priv)->sae_blacklist_table->table_size_power;
	int i;
	unsigned long flags;
	struct candidate *peer = NULL;
	log("");
	for (i = 0; i < tbl_sz; i++) {
		SAVE_INT_AND_CLI(flags);
		if (GET_ROOT(priv)->sae_blacklist_table->entry_array[i].dirty) {
			peer = ((struct candidate *)GET_ROOT(priv)->sae_blacklist_table->entry_array[i].data);
			remove_from_blacklist(priv, peer->peer_mac);
		}
		RESTORE_INT(flags);
	}
	return 0;
}

int clean_up_sae_peer_table(struct rtl8192cd_priv *priv)
{
	int tbl_sz = 1 << GET_ROOT(priv)->sae_peer_table->table_size_power;
	int i;
	unsigned long now = jiffies;
	unsigned long flags;
	struct candidate *peer = NULL;
	log("");
	for (i = 0; i < tbl_sz; i++) {
		SAVE_INT_AND_CLI(flags);
		if (GET_ROOT(priv)->sae_peer_table->entry_array[i].dirty) {
			peer = ((struct candidate *)GET_ROOT(priv)->sae_peer_table->entry_array[i].data);
			delete_peer(priv, peer->peer_mac);
		}
		RESTORE_INT(flags);
	}
	return 0;
}

/*rtk add this function for start STA mode WPA3 SAE procedure*/
int client_send_commit_to_peer(struct rtl8192cd_priv *priv, unsigned char *da)
{
	/*
	 * This is actually not part of the parent state machine but handling
	 * it here makes the rest of the protocol instance state machine nicer.
	 *
	 * a new mesh point! auth_req transitions from state "NOTHING" to "COMMITTED"
	 */
	struct candidate *peer = NULL;
#ifndef SMP_SYNC
	unsigned long flags;
#endif
	if (on_blacklist(priv, da)) {
		sae_debug(SAE_DEBUG_ERR, "peer[%pm] on blocklist", da);
		return -1;
	}
	if ((peer = HASH_SEARCH(GET_ROOT(priv)->sae_peer_table, da)) != NULL) {
		sae_debug(SAE_DEBUG_ERR, "peer[%pm] dealing on going", da);
		return -1;
	}
	/*ONGL: New a peer */
	if ((peer = create_candidate(priv, da, GET_MY_HWADDR, 0)) == NULL) {
		sae_debug(SAE_DEBUG_ERR, "peer[%pm] create_candidate fail", da);
		return -1;
	}
	//peer->cookie = cookie;
	/*
	 * assign the first group in the list as the one to try
	 */

	if (assign_group_to_peer(priv, priv->gd, da) < 0) {
		sae_debug(SAE_DEBUG_ERR, "peer[%pm] assign_group_to_peer fail", da);
		fin(priv, WLAN_STATUS_UNSPECIFIED_FAILURE, peer->peer_mac, NULL, 0);
		SAVE_INT_AND_CLI(flags);
		delete_peer(priv, peer->peer_mac);
		RESTORE_INT(flags);

	} else {
		/*assign_group_to_peer done */
		log("[TX][SAE COMMIT]to peer[%pm]", da);

		/*send commit to peer */
		commit_to_peer(priv, da, NULL, 0);
		peer->t0 = jiffies;
		SAVE_INT_AND_CLI(flags);
		peer->state = SAE_COMMITTED;
		RESTORE_INT(flags);

		//log(" peer FSM [%pm] state=[%d][%s]", peer->peer_mac, peer->state, state_to_string(peer->state));
	}
}
#endif
