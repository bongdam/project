
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

#define MAX_DATA_SIZE 2048
#define LEN_LLC			8

int rtk_gcmp_encrypt(struct rtl8192cd_priv *priv, unsigned char *pwlhdr,
		     unsigned char *pllc,
		     unsigned char *pfr, unsigned int frlen, unsigned char *pmic, unsigned char isMgmt)
{
	static unsigned char plain[MAX_DATA_SIZE];
	static unsigned char crypt[MAX_DATA_SIZE];
	unsigned int hdrlen, ttkeylen, plain_len = 0;
	unsigned char *da = get_da(pwlhdr);
	unsigned char *ttkey, pn48;
	unsigned int keyid;
	struct stat_info *pstat = NULL;

	unsigned char aad[30], nonce[12], *enc, *gcmp_hdr, *crypt, *auth;
	signed int aad_len, enc_len;

	hdrlen = get_hdrlen(priv, pwlhdr);

	if (IS_MCAST(da)) {
		if (priv->pmib->dot11GroupKeysTable.keyid == GKEY_ID_SECOND) {
			ttkey = GET_GROUP_ENCRYP2_KEY;
			ttkeylen = GET_GROUP_ENCRYP_KEYLEN;
		} else {
			ttkey = GET_GROUP_ENCRYP_KEY;
			ttkeylen = GET_GROUP_IDX2_ENCRYP_KEYLEN;
		}
		pn48 = GET_GROUP_ENCRYP_PN;
		keyid = priv->pmib->dot11GroupKeysTable.keyid;
	} else {
		pstat = get_stainfo(priv, da);
		if (pstat == NULL) {
			DEBUG_ERR("tx aes pstat == NULL\n");
			return;
		}
		ttkey = GET_UNICAST_ENCRYP_KEY;
		ttkeylen = GET_UNICAST_ENCRYP_KEYLEN;
		pn48 = GET_UNICAST_ENCRYP_PN;
	}

	if (pllc) {
		memcpy(plain, pllc, LEN_LLC);
		memcpy(plain + LEN_LLC, pfr, frlen);
		plain_len = LEN_LLC + frlen;
	} else {
		memcpy(plain, pfr, frlen);
		plain_len = frlen;
	}

	gcmp_hdr = pwlhdr + hdrlen;
	auth = pmic;
	memset(aad, 0, sizeof(aad));
	gcmp_aad_nonce(pwlhdr, gcmp_hdr, aad, &aad_len, nonce);	//gen "aad & nonce" from "mac & gcmp" hdr

	if (aes_gcm_ae(ttkey, ttkeylen, nonce, sizeof(nonce), plain, plain_len, aad, aad_len, crypt, auth) < 0) {
		return _FAIL;
	}

	if (pllc) {
		memcpy(pllc, crypt, LEN_LLC);
		memcpy(pfr, crypt + LEN_LLC, frlen);
	} else {
		memcpy(pfr, crypt, frlen);
	}

	return _SUCCESS;
}
