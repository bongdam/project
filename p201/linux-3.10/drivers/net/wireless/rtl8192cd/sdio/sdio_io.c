/*
 *  SDIO IO common routines
 *
 *  $Id: sdio_core.c,v 1.27.2.31 2010/12/31 08:37:43 family Exp $
 *
 *  Copyright (c) 2009 Realtek Semiconductor Corp.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#define _SDIO_IO_C_

#ifdef __KERNEL__
#include <linux/mmc/host.h>
#include <linux/mmc/card.h>
#include <linux/mmc/sdio.h>
#endif

#include "8192cd.h"
#include "8192cd_headers.h"
#include "8192cd_debug.h"

#define SDIO_ERR_VAL8	0xEA
#define SDIO_ERR_VAL16	0xEAEA
#define SDIO_ERR_VAL32	0xEAEAEAEA

u8 sd_f0_read8(struct rtl8192cd_priv *priv, u32 addr, s32 *err)
{
	u8 v;
	struct sdio_func *func;
	
	func = priv->pshare->psdio_func;

	sdio_claim_host(func);
	v = sdio_f0_readb(func, addr, err);
	sdio_release_host(func);
	if (err && *err)
		printk(KERN_ERR "%s: FAIL!(%d) addr=0x%05x\n", __func__, *err, addr);

	return v;
}

void sd_f0_write8(struct rtl8192cd_priv *priv, u32 addr, u8 v, s32 *err)
{
	struct sdio_func *func;

	func = priv->pshare->psdio_func;

	sdio_claim_host(func);
	sdio_f0_writeb(func, v, addr, err);
	sdio_release_host(func);
	if (err && *err)
		printk(KERN_ERR "%s: FAIL!(%d) addr=0x%05x val=0x%02x\n", __func__, *err, addr, v);
}

/*
 * Return:
 *	0		Success
 *	others	Fail
 */
s32 _sd_cmd52_read(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *pdata)
{
	int err, i;
	struct sdio_func *func;

	err = 0;
	func = priv->pshare->psdio_func;

	for (i = 0; i < cnt; i++) {
		pdata[i] = sdio_readb(func, addr+i, &err);
		if (err) {
			printk(KERN_ERR "%s: FAIL!(%d) addr=0x%05x\n", __func__, err, addr);
			break;
		}
	}

	return err;
}

/*
 * Return:
 *	0		Success
 *	others	Fail
 */
s32 sd_cmd52_read(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *pdata)
{
	int err;
	struct sdio_func *func;

	err = 0;
	func = priv->pshare->psdio_func;

	sdio_claim_host(func);
	err = _sd_cmd52_read(priv, addr, cnt, pdata);
	sdio_release_host(func);

	return err;
}

/*
 * Return:
 *	0		Success
 *	others	Fail
 */
s32 _sd_cmd52_write(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *pdata)
{
	int err, i;
	struct sdio_func *func;

	err = 0;
	func = priv->pshare->psdio_func;

	for (i = 0; i < cnt; i++) {
		sdio_writeb(func, pdata[i], addr+i, &err);
		if (err) {
			printk(KERN_ERR "%s: FAIL!(%d) addr=0x%05x val=0x%02x\n", __func__, err, addr, pdata[i]);
			break;
		}
	}

	return err;
}

/*
 * Return:
 *	0		Success
 *	others	Fail
 */
s32 sd_cmd52_write(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *pdata)
{
	int err;
	struct sdio_func *func;

	err = 0;
	func = priv->pshare->psdio_func;

	sdio_claim_host(func);
	err = _sd_cmd52_write(priv, addr, cnt, pdata);
	sdio_release_host(func);

	return err;
}

u8 _sd_read8(struct rtl8192cd_priv *priv, u32 addr, s32 *err)
{
	u8 v;
	struct sdio_func *func;

	func = priv->pshare->psdio_func;

	//sdio_claim_host(func);
	v = sdio_readb(func, addr, err);
	//sdio_release_host(func);
	if (err && *err)
		printk(KERN_ERR "%s: FAIL!(%d) addr=0x%05x\n", __func__, *err, addr);

	return v;
}

u8 sd_read8(struct rtl8192cd_priv *priv, u32 addr, s32 *err)
{
	u8 v;
	struct sdio_func *func;

	func = priv->pshare->psdio_func;

	sdio_claim_host(func);
	v = sdio_readb(func, addr, err);
	sdio_release_host(func);
	if (err && *err)
		printk(KERN_ERR "%s: FAIL!(%d) addr=0x%05x\n", __func__, *err, addr);

	return v;
}

u16 sd_read16(struct rtl8192cd_priv *priv, u32 addr, s32 *err)
{
	u16 v;
	struct sdio_func *func;

	func = priv->pshare->psdio_func;

	sdio_claim_host(func);
	v = sdio_readw(func, addr, err);
	sdio_release_host(func);
	if (err && *err)
		printk(KERN_ERR "%s: FAIL!(%d) addr=0x%05x\n", __func__, *err, addr);

	return  v;
}

u32 _sd_read32(struct rtl8192cd_priv *priv, u32 addr, s32 *err)
{
	u32 v;
	struct sdio_func *func;

	func = priv->pshare->psdio_func;

	//sdio_claim_host(func);
	v = sdio_readl(func, addr, err);
	//sdio_release_host(func);
	if (err && *err)
		printk(KERN_ERR "%s: FAIL!(%d) addr=0x%05x\n", __func__, *err, addr);

	return  v;
}

u32 sd_read32(struct rtl8192cd_priv *priv, u32 addr, s32 *err)
{
	u32 v;
	struct sdio_func *func;

	func = priv->pshare->psdio_func;

	sdio_claim_host(func);
	v = sdio_readl(func, addr, err);
	sdio_release_host(func);
	if (err && *err)
		printk(KERN_ERR "%s: FAIL!(%d) addr=0x%05x\n", __func__, *err, addr);

	return  v;
}

void sd_write8(struct rtl8192cd_priv *priv, u32 addr, u8 v, s32 *err)
{
	struct sdio_func *func;

	func = priv->pshare->psdio_func;

	sdio_claim_host(func);
	sdio_writeb(func, v, addr, err);
	sdio_release_host(func);
	if (err && *err)
		printk(KERN_ERR "%s: FAIL!(%d) addr=0x%05x val=0x%02x\n", __func__, *err, addr, v);
}

void sd_write16(struct rtl8192cd_priv *priv, u32 addr, u16 v, s32 *err)
{
	struct sdio_func *func;

	func = priv->pshare->psdio_func;

	sdio_claim_host(func);
	sdio_writew(func, v, addr, err);
	sdio_release_host(func);
	if (err && *err)
		printk(KERN_ERR "%s: FAIL!(%d) addr=0x%05x val=0x%04x\n", __func__, *err, addr, v);
}

void _sd_write32(struct rtl8192cd_priv *priv, u32 addr, u32 v, s32 *err)
{
	struct sdio_func *func;

	func = priv->pshare->psdio_func;

	//sdio_claim_host(func);
	sdio_writel(func, v, addr, err);
	//sdio_release_host(func);
	if (err && *err)
		printk(KERN_ERR "%s: FAIL!(%d) addr=0x%05x val=0x%08x\n", __func__, *err, addr, v);
}

void sd_write32(struct rtl8192cd_priv *priv, u32 addr, u32 v, s32 *err)
{
	struct sdio_func *func;

	func = priv->pshare->psdio_func;

	sdio_claim_host(func);
	sdio_writel(func, v, addr, err);
	sdio_release_host(func);
	if (err && *err)
		printk(KERN_ERR "%s: FAIL!(%d) addr=0x%05x val=0x%08x\n", __func__, *err, addr, v);
}

/*
 * Use CMD53 to read data from SDIO device.
 * This function MUST be called after sdio_claim_host() or
 * in SDIO ISR(host had been claimed).
 *
 * Parameters:
 *	psdio	pointer of SDIO_DATA
 *	addr	address to read
 *	cnt		amount to read
 *	pdata	pointer to put data, this should be a "DMA:able scratch buffer"!
 *
 * Return:
 *	0		Success
 *	others	Fail
 */
s32 _sd_read(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, void *pdata)
{
	int err;
	struct sdio_func *func;

	func = priv->pshare->psdio_func;

	if (unlikely((cnt==1) || (cnt==2)))
	{
		int i;
		u8 *pbuf = (u8*)pdata;

		for (i = 0; i < cnt; i++)
		{
			*(pbuf+i) = sdio_readb(func, addr+i, &err);

			if (err) {
				printk(KERN_ERR "%s: FAIL!(%d) addr=0x%05x\n", __func__, err, addr);
				break;
			}
		}
		return err;
	}

	err = sdio_memcpy_fromio(func, pdata, addr, cnt);
	if (err) {
		printk(KERN_ERR "%s: FAIL(%d)! ADDR=%#x Size=%d\n", __func__, err, addr, cnt);
	}

	return err;
}

/*
 * Use CMD53 to read data from SDIO device.
 *
 * Parameters:
 *	psdio	pointer of SDIO_DATA
 *	addr	address to read
 *	cnt		amount to read
 *	pdata	pointer to put data, this should be a "DMA:able scratch buffer"!
 *
 * Return:
 *	0		Success
 *	others	Fail
 */
s32 sd_read(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, void *pdata)
{
	s32 err;
	struct sdio_func *func;

	func = priv->pshare->psdio_func;

	sdio_claim_host(func);
	err = _sd_read(priv, addr, cnt, pdata);
	sdio_release_host(func);

	return err;
}

/*
 * Use CMD53 to write data to SDIO device.
 * This function MUST be called after sdio_claim_host() or
 * in SDIO ISR(host had been claimed).
 *
 * Parameters:
 *	psdio	pointer of SDIO_DATA
 *	addr	address to write
 *	cnt		amount to write
 *	pdata	data pointer, this should be a "DMA:able scratch buffer"!
 *
 * Return:
 *	0		Success
 *	others	Fail
 */
s32 _sd_write(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, void *pdata)
{
	int err;
	struct sdio_func *func;
	u32 size;

	func = priv->pshare->psdio_func;
//	size = sdio_align_size(func, cnt);

	if (unlikely((cnt==1) || (cnt==2)))
	{
		int i;
		u8 *pbuf = (u8*)pdata;

		for (i = 0; i < cnt; i++)
		{
			sdio_writeb(func, *(pbuf+i), addr+i, &err);
			if (err) {
				printk(KERN_ERR "%s: FAIL!(%d) addr=0x%05x val=0x%02x\n", __func__, err, addr, *(pbuf+i));
				break;
			}
		}

		return err;
	}

	size = cnt;
	err = sdio_memcpy_toio(func, addr, pdata, size);
	if (err) {
		printk(KERN_ERR "%s: FAIL(%d)! ADDR=%#x Size=%d(%d)\n", __func__, err, addr, cnt, size);
	}
	
	return err;
}

/*
 * Use CMD53 to write data to SDIO device.
 *
 * Parameters:
 *  psdio	pointer of SDIO_DATA
 *  addr	address to write
 *  cnt		amount to write
 *  pdata	data pointer, this should be a "DMA:able scratch buffer"!
 *
 * Return:
 *  0		Success
 *  others	Fail
 */
s32 sd_write(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, void *pdata)
{
	s32 err;
	struct sdio_func *func;

	func = priv->pshare->psdio_func;

	sdio_claim_host(func);
	err = _sd_write(priv, addr, cnt, pdata);
	sdio_release_host(func);

	return err;
}

extern void HalSdioGetCmdAddr8723ASdio(struct rtl8192cd_priv *priv, u8 DeviceID, u32 Addr, u32* pCmdAddr);
extern u8 get_deviceid(u32 addr);
extern u32 _cvrt2ftaddr(const u32 addr, u8 *pdeviceId, u16 *poffset);

u8 _sdio_read8(struct rtl8192cd_priv *priv, u32 addr, s32 *err)
{
	u32 ftaddr;
	u8 val;

	ftaddr = _cvrt2ftaddr(addr, NULL, NULL);
	val = _sd_read8(priv, ftaddr, err);
	
	return val;
}

u8 sdio_read8(struct rtl8192cd_priv *priv, u32 addr, s32 *err)
{
	u32 ftaddr;
	u8 val;

	ftaddr = _cvrt2ftaddr(addr, NULL, NULL);
	val = sd_read8(priv, ftaddr, err);

	return val;
}

u16 sdio_read16(struct rtl8192cd_priv *priv, u32 addr, s32 *err)
{
	u32 ftaddr;
	u16 val;
	s32 ret;

	ftaddr = _cvrt2ftaddr(addr, NULL, NULL);
	ret = sd_cmd52_read(priv, ftaddr, 2, (u8*)&val);
	val = le16_to_cpu(val);
	
	if (err)
		*err = ret;

	return val;
}

u32 _sdio_read32(struct rtl8192cd_priv *priv, u32 addr, s32 *err)
{
	u8 deviceId;
	u16 offset;
	u32 ftaddr;
	u8 shift;
	u32 val;
	s32 ret;

	ftaddr = _cvrt2ftaddr(addr, &deviceId, &offset);

	if (((deviceId == WLAN_IOREG_DEVICE_ID) && (offset < 0x100))
		|| (FALSE == GET_HAL_INTF_DATA(priv)->bMacPwrCtrlOn)
#ifdef CONFIG_LPS_LCLK
		|| (TRUE == padapter->pwrctrlpriv.bFwCurrentInPSMode)
#endif
		)
        {
		ret = _sd_cmd52_read(priv, ftaddr, 4, (u8*)&val);
#ifdef SDIO_DEBUG_IO
		if (ret) {
			printk(KERN_ERR "%s: Mac Power off, Read FAIL(%d)! addr=0x%x\n", __func__, ret, addr);
			return SDIO_ERR_VAL32;
		}
#endif
		val = le32_to_cpu(val);
		return val;
	}

	// 4 bytes alignment
	shift = ftaddr & 0x3;
	if (shift == 0) {
		val = _sd_read32(priv, ftaddr, &ret);
	} else {
		u8 tmpbuf[8];

		ftaddr &= ~0x3;
		ret = _sd_read(priv, ftaddr, 8, tmpbuf);
		memcpy(&val, tmpbuf+shift, 4);
		val = le32_to_cpu(val);
	}

	if (err)
		*err = ret;

	return val;
}

u32 sdio_read32(struct rtl8192cd_priv *priv, u32 addr, s32 *err)
{
	u8 deviceId;
	u16 offset;
	u32 ftaddr;
	u8 shift;
	u32 val;
	s32 ret;

	ftaddr = _cvrt2ftaddr(addr, &deviceId, &offset);

	if (((deviceId == WLAN_IOREG_DEVICE_ID) && (offset < 0x100))
		|| (FALSE == GET_HAL_INTF_DATA(priv)->bMacPwrCtrlOn)
#ifdef CONFIG_LPS_LCLK
		|| (TRUE == padapter->pwrctrlpriv.bFwCurrentInPSMode)
#endif
		)
	{
		ret = sd_cmd52_read(priv, ftaddr, 4, (u8*)&val);
#ifdef SDIO_DEBUG_IO
		if (ret) {
			printk(KERN_ERR "%s: Mac Power off, Read FAIL(%d)! addr=0x%x\n", __func__, ret, addr);
			return SDIO_ERR_VAL32;
		}
#endif
		val = le32_to_cpu(val);
		return val;
	}

	// 4 bytes alignment
	shift = ftaddr & 0x3;
	if (shift == 0) {
		val = sd_read32(priv, ftaddr, &ret);
	} else {
		u8 tmpbuf[8];

		ftaddr &= ~0x3;
		ret = sd_read(priv, ftaddr, 8, tmpbuf);
		memcpy(&val, tmpbuf+shift, 4);
		val = le32_to_cpu(val);
	}

	if (err)
		*err = ret;

	return val;
}

s32 sdio_readN(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *pbuf)
{
	u8 deviceId;
	u16 offset;
	u32 ftaddr;
	u8 shift;
	s32 err;

	err = 0;
	ftaddr = _cvrt2ftaddr(addr, &deviceId, &offset);

	if (((deviceId == WLAN_IOREG_DEVICE_ID) && (offset < 0x100))
		|| (FALSE == GET_HAL_INTF_DATA(priv)->bMacPwrCtrlOn)
#ifdef CONFIG_LPS_LCLK
		|| (TRUE == padapter->pwrctrlpriv.bFwCurrentInPSMode)
#endif
		)
	{
		err = sd_cmd52_read(priv, ftaddr, cnt, pbuf);
		return err;
	}

	// 4 bytes alignment
	shift = ftaddr & 0x3;
	if (shift == 0) {
		err = sd_read(priv, ftaddr, cnt, pbuf);
	} else {
		u8 *ptmpbuf;
		u32 n;

		ftaddr &= ~0x3;
		n = cnt + shift;
		ptmpbuf = rtw_malloc(n);
		if (NULL == ptmpbuf) return -ENOMEM;
		
		err = sd_read(priv, ftaddr, n, ptmpbuf);
		if (!err)
			memcpy(pbuf, ptmpbuf+shift, cnt);
		
		rtw_mfree(ptmpbuf, n);
	}

	return err;
}

s32 sdio_write8(struct rtl8192cd_priv *priv, u32 addr, u8 val)
{
	u32 ftaddr;
	s32 err;

	ftaddr = _cvrt2ftaddr(addr, NULL, NULL);
	sd_write8(priv, ftaddr, val, &err);

	return err;
}

s32 sdio_write16(struct rtl8192cd_priv *priv, u32 addr, u16 val)
{
	u32 ftaddr;
	s32 err;

	ftaddr = _cvrt2ftaddr(addr, NULL, NULL);
	val = cpu_to_le16(val);
	err = sd_cmd52_write(priv, ftaddr, 2, (u8*)&val);

	return err;
}

s32 _sdio_write32(struct rtl8192cd_priv *priv, u32 addr, u32 val)
{
	u8 deviceId;
	u16 offset;
	u32 ftaddr;
	u8 shift;
	s32 err;

	err = 0;
	ftaddr = _cvrt2ftaddr(addr, &deviceId, &offset);

	if (((deviceId == WLAN_IOREG_DEVICE_ID) && (offset < 0x100))
		|| (FALSE == GET_HAL_INTF_DATA(priv)->bMacPwrCtrlOn)
#ifdef CONFIG_LPS_LCLK
		|| (TRUE == padapter->pwrctrlpriv.bFwCurrentInPSMode)
#endif
		)
	{
		val = cpu_to_le32(val);
		err = _sd_cmd52_write(priv, ftaddr, 4, (u8*)&val);
		return err;
	}

	// 4 bytes alignment
	shift = ftaddr & 0x3;
#if 1
	if (shift == 0)
	{
		_sd_write32(priv, ftaddr, val, &err);
	}
	else
	{
		val = cpu_to_le32(val);
		err = _sd_cmd52_write(priv, ftaddr, 4, (u8*)&val);
	}
#else
	if (shift == 0) {
		sd_write32(priv, ftaddr, val, &err);
	} else {
		u8 *ptmpbuf;

		ptmpbuf = (u8*)rtw_malloc(8);
		if (NULL == ptmpbuf) return -ENOMEM;

		ftaddr &= ~0x3;
		err = sd_read(priv, ftaddr, 8, ptmpbuf);
		if (err) {
			_rtw_mfree(ptmpbuf, 8);
			return err;
		}
		val = cpu_to_le32(val);
		memcpy(ptmpbuf+shift, &val, 4);
		err = sd_write(priv, ftaddr, 8, ptmpbuf);

		rtw_mfree(ptmpbuf, 8);
	}
#endif
	
	return err;
}

s32 sdio_write32(struct rtl8192cd_priv *priv, u32 addr, u32 val)
{
	u8 deviceId;
	u16 offset;
	u32 ftaddr;
	u8 shift;
	s32 err;

	err = 0;
	ftaddr = _cvrt2ftaddr(addr, &deviceId, &offset);

	if (((deviceId == WLAN_IOREG_DEVICE_ID) && (offset < 0x100))
		|| (FALSE == GET_HAL_INTF_DATA(priv)->bMacPwrCtrlOn)
#ifdef CONFIG_LPS_LCLK
		|| (TRUE == padapter->pwrctrlpriv.bFwCurrentInPSMode)
#endif
		)
	{
		val = cpu_to_le32(val);
		err = sd_cmd52_write(priv, ftaddr, 4, (u8*)&val);
		return err;
	}

	// 4 bytes alignment
	shift = ftaddr & 0x3;
#if 1
	if (shift == 0)
	{
		sd_write32(priv, ftaddr, val, &err);
	}
	else
	{
		val = cpu_to_le32(val);
		err = sd_cmd52_write(priv, ftaddr, 4, (u8*)&val);
	}
#else
	if (shift == 0) {
		sd_write32(priv, ftaddr, val, &err);
	} else {
		u8 *ptmpbuf;

		ptmpbuf = (u8*)rtw_malloc(8);
		if (NULL == ptmpbuf) return -ENOMEM;

		ftaddr &= ~0x3;
		err = sd_read(priv, ftaddr, 8, ptmpbuf);
		if (err) {
			rtw_mfree(ptmpbuf, 8);
			return err;
		}
		val = cpu_to_le32(val);
		memcpy(ptmpbuf+shift, &val, 4);
		err = sd_write(priv, ftaddr, 8, ptmpbuf);

		rtw_mfree(ptmpbuf, 8);
	}
#endif

	return err;
}

s32 sdio_writeN(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8* pbuf)
{
	u8 deviceId;
	u16 offset;
	u32 ftaddr;
	u8 shift;
	s32 err;

	err = 0;
	ftaddr = _cvrt2ftaddr(addr, &deviceId, &offset);

	if (((deviceId == WLAN_IOREG_DEVICE_ID) && (offset < 0x100))
		|| (FALSE == GET_HAL_INTF_DATA(priv)->bMacPwrCtrlOn)
#ifdef CONFIG_LPS_LCLK
		|| (TRUE == padapter->pwrctrlpriv.bFwCurrentInPSMode)
#endif
		)
	{
		err = sd_cmd52_write(priv, ftaddr, cnt, pbuf);
		return err;
	}

	shift = ftaddr & 0x3;
	if (shift == 0) {
		err = sd_write(priv, ftaddr, cnt, pbuf);
	} else {
		u8 *ptmpbuf;
		u32 n;

		ftaddr &= ~0x3;
		n = cnt + shift;
		ptmpbuf = rtw_malloc(n);
		if (NULL == ptmpbuf) return -ENOMEM;
		err = sd_read(priv, ftaddr, 4, ptmpbuf);
		if (err) {
			rtw_mfree(ptmpbuf, n);
			return err;
		}
		memcpy(ptmpbuf+shift, pbuf, cnt);
		err = sd_write(priv, ftaddr, n, ptmpbuf);
		rtw_mfree(ptmpbuf, n);
	}

	return err;
}

/*
 * Description:
 *	Read from RX FIFO
 *	Round read size to block size,
 *	and make sure data transfer will be done in one command.
 *
 * Parameters:
 *	pintfhdl	a pointer of intf_hdl
 *	addr		port ID
 *	cnt			size to read
 *	rmem		address to put data
 *
 * Return:
 *	= 0		Success
 *	!= 0		Fail
 */
u32 sdio_read_port(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *mem)
{
	struct priv_shared_info *pshare = priv->pshare;
	HAL_INTF_DATA_TYPE *pHalData = GET_HAL_INTF_DATA(priv);
	s32 err;

	HalSdioGetCmdAddr8723ASdio(priv, addr, pHalData->SdioRxFIFOCnt++, &addr);

	cnt = _RND4(cnt);
	if (cnt > pshare->block_transfer_len)
		cnt = _RND(cnt, pshare->block_transfer_len);

//	cnt = sdio_align_size(cnt);

	err = _sd_read(priv, addr, cnt, mem);
	//err = sd_read(priv, addr, cnt, mem);
	
	return err;
}

/*
 * Description:
 *	Write to TX FIFO
 *	Align write size block size,
 *	and make sure data could be written in one command.
 *
 * Parameters:
 *	pintfhdl	a pointer of intf_hdl
 *	addr		port ID
 *	cnt			size to write
 *	wmem		data pointer to write
 *
 * Return:
 *	= 0		Success
 *	!= 0		Fail
 */
u32 sdio_write_port(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *mem)
{
	s32 err;
	struct priv_shared_info *pshare = priv->pshare;
	struct xmit_buf *pxmitbuf = (struct xmit_buf *)mem;
	const int q_num = pxmitbuf->q_num;
#ifdef SDIO_STATISTICS_TIME
	struct timeval start, now;
#endif

	cnt = _RND4(cnt);
	HalSdioGetCmdAddr8723ASdio(priv, addr, cnt >> 2, &addr);

	if (cnt > pshare->block_transfer_len)
		cnt = _RND(cnt, pshare->block_transfer_len);
//	cnt = sdio_align_size(cnt);

#ifdef SDIO_STATISTICS_TIME
	do_gettimeofday(&start);
#endif

	err = sd_write(priv, addr, cnt, pxmitbuf->pkt_data);
	pxmitbuf->status = err;
	
#ifdef SDIO_STATISTICS
	if (BE_QUEUE == q_num) {
		pshare->writeport_total_count[pxmitbuf->agg_num-1]++;
#ifdef SDIO_STATISTICS_TIME
		do_gettimeofday(&now);
		pshare->writeport_total_time[pxmitbuf->agg_num-1] += (timeval_to_us(&now) -timeval_to_us(&start));
#endif
	}
#endif

//	rtw_sctx_done_err(&xmitbuf->sctx,
//		err ? RTW_SCTX_DONE_WRITE_PORT_ERR : RTW_SCTX_DONE_SUCCESS);

	if (err) {
		printk("%s, error=%d\n", __func__, err);
	}
	
	if ((q_num >= BK_QUEUE) && (q_num <= VO_QUEUE)) {
		pshare->low_traffic_xmit_stats[q_num] += pxmitbuf->agg_num;
	}
	
	return err;
}

/*
 * Todo: align address to 4 bytes.
 */
s32 _sdio_local_read(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *pbuf)
{
	s32 err;
	u8 *ptmpbuf;
	u32 n;

	HalSdioGetCmdAddr8723ASdio(priv, SDIO_LOCAL_DEVICE_ID, addr, &addr);

	if ((FALSE == GET_HAL_INTF_DATA(priv)->bMacPwrCtrlOn)
#ifdef CONFIG_LPS_LCLK
//		|| (_TRUE == padapter->pwrctrlpriv.bFwCurrentInPSMode)
#endif
		)
	{
		err = _sd_cmd52_read(priv, addr, cnt, pbuf);
		return err;
	}

        n = _RND4(cnt);
	ptmpbuf = (u8*)rtw_malloc(n);
	if (NULL == ptmpbuf)
		return -ENOMEM;

	err = _sd_read(priv, addr, n, ptmpbuf);
	if (!err)
		memcpy(pbuf, ptmpbuf, cnt);

	rtw_mfree(ptmpbuf, n);

	return err;
}

/*
 * Todo: align address to 4 bytes.
 */
s32 sdio_local_read(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *pbuf)
{
	s32 err;
	u8 *ptmpbuf;
	u32 n;

	HalSdioGetCmdAddr8723ASdio(priv, SDIO_LOCAL_DEVICE_ID, addr, &addr);

	if ((FALSE == GET_HAL_INTF_DATA(priv)->bMacPwrCtrlOn)
#ifdef CONFIG_LPS_LCLK
		|| (TRUE == padapter->pwrctrlpriv.bFwCurrentInPSMode)
#endif
		)
	{
		err = sd_cmd52_read(priv, addr, cnt, pbuf);
		return err;
	}

        n = _RND4(cnt);
	ptmpbuf = (u8*)rtw_malloc(n);
	if (NULL == ptmpbuf)
		return -ENOMEM;

	err = sd_read(priv, addr, n, ptmpbuf);
	if (!err)
		memcpy(pbuf, ptmpbuf, cnt);

	rtw_mfree(ptmpbuf, n);

	return err;
}

/*
 * Todo: align address to 4 bytes.
 */
s32 _sdio_local_write(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *pbuf)
{
	s32 err;
	u8 *ptmpbuf;

	if (addr & 0x3)
		printk("%s, address must be 4 bytes alignment\n", __FUNCTION__);

	if (cnt & 0x3)
		printk("%s, size must be the multiple of 4 \n", __FUNCTION__);

	HalSdioGetCmdAddr8723ASdio(priv, SDIO_LOCAL_DEVICE_ID, addr, &addr);

	if ((FALSE == GET_HAL_INTF_DATA(priv)->bMacPwrCtrlOn)
#ifdef CONFIG_LPS_LCLK
//		|| (TRUE == padapter->pwrctrlpriv.bFwCurrentInPSMode)
#endif
		)
	{
		err = _sd_cmd52_write(priv, addr, cnt, pbuf);
		return err;
	}

        ptmpbuf = (u8*)rtw_malloc(cnt);
	if (NULL == ptmpbuf)
		return -ENOMEM;

	memcpy(ptmpbuf, pbuf, cnt);

	err = _sd_write(priv, addr, cnt, ptmpbuf);

	rtw_mfree(ptmpbuf, cnt);

	return err;
}

/*
 * Todo: align address to 4 bytes.
 */
s32 sdio_local_write(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *pbuf)
{
	s32 err;
	u8 *ptmpbuf;

	if (addr & 0x3)
		printk("%s, address must be 4 bytes alignment\n", __FUNCTION__);

	if (cnt & 0x3)
		printk("%s, size must be the multiple of 4 \n", __FUNCTION__);

	HalSdioGetCmdAddr8723ASdio(priv, SDIO_LOCAL_DEVICE_ID, addr, &addr);

	if ((FALSE == GET_HAL_INTF_DATA(priv)->bMacPwrCtrlOn)
#ifdef CONFIG_LPS_LCLK
		|| (TRUE == padapter->pwrctrlpriv.bFwCurrentInPSMode)
#endif
		)
	{
		err = sd_cmd52_write(priv, addr, cnt, pbuf);
		return err;
	}

        ptmpbuf = (u8*)rtw_malloc(cnt);
	if (NULL == ptmpbuf)
		return -ENOMEM;

	memcpy(ptmpbuf, pbuf, cnt);

	err = sd_write(priv, addr, cnt, ptmpbuf);

	rtw_mfree(ptmpbuf, cnt);

	return err;
}

u8 SdioLocalCmd52Read1Byte(struct rtl8192cd_priv *priv, u32 addr)
{
	u8 val = 0;

	HalSdioGetCmdAddr8723ASdio(priv, SDIO_LOCAL_DEVICE_ID, addr, &addr);
	sd_cmd52_read(priv, addr, 1, &val);

	return val;
}

u16 SdioLocalCmd52Read2Byte(struct rtl8192cd_priv *priv, u32 addr)
{
	u16 val = 0;

	HalSdioGetCmdAddr8723ASdio(priv, SDIO_LOCAL_DEVICE_ID, addr, &addr);
	sd_cmd52_read(priv, addr, 2, (u8*)&val);

	val = le16_to_cpu(val);

	return val;
}

u32 SdioLocalCmd52Read4Byte(struct rtl8192cd_priv *priv, u32 addr)
{
	u32 val = 0;

	HalSdioGetCmdAddr8723ASdio(priv, SDIO_LOCAL_DEVICE_ID, addr, &addr);
	sd_cmd52_read(priv, addr, 4, (u8*)&val);

	val = le32_to_cpu(val);

	return val;
}

u32 SdioLocalCmd53Read4Byte(struct rtl8192cd_priv *priv, u32 addr)
{
	u32 val;

	val = 0;
	HalSdioGetCmdAddr8723ASdio(priv, SDIO_LOCAL_DEVICE_ID, addr, &addr);
	if ((FALSE == GET_HAL_INTF_DATA(priv)->bMacPwrCtrlOn)
#ifdef CONFIG_LPS_LCLK
		|| (TRUE == padapter->pwrctrlpriv.bFwCurrentInPSMode)
#endif
		)
	{
		sd_cmd52_read(priv, addr, 4, (u8*)&val);
		val = le32_to_cpu(val);
	}
	else
		val = sd_read32(priv, addr, NULL);

	return val;
}

void SdioLocalCmd52Write1Byte(struct rtl8192cd_priv *priv, u32 addr, u8 v)
{
	HalSdioGetCmdAddr8723ASdio(priv, SDIO_LOCAL_DEVICE_ID, addr, &addr);
	sd_cmd52_write(priv, addr, 1, &v);
}

void SdioLocalCmd52Write2Byte(struct rtl8192cd_priv *priv, u32 addr, u16 v)
{
	HalSdioGetCmdAddr8723ASdio(priv, SDIO_LOCAL_DEVICE_ID, addr, &addr);
	v = cpu_to_le16(v);
	sd_cmd52_write(priv, addr, 2, (u8*)&v);
}

void SdioLocalCmd52Write4Byte(struct rtl8192cd_priv *priv, u32 addr, u32 v)
{
	HalSdioGetCmdAddr8723ASdio(priv, SDIO_LOCAL_DEVICE_ID, addr, &addr);
	v = cpu_to_le32(v);
	sd_cmd52_write(priv, addr, 4, (u8*)&v);
}

static int mmc_io_rw_direct_host(struct mmc_host *host, int write, unsigned fn,
	unsigned addr, u8 in, u8 *out)
{
	struct mmc_command cmd = {0};
	int err;

	BUG_ON(!host);
	BUG_ON(fn > 7);

	/* sanity check */
	if (addr & ~0x1FFFF)
		return -EINVAL;

	cmd.opcode = SD_IO_RW_DIRECT;
	cmd.arg = write ? 0x80000000 : 0x00000000;
	cmd.arg |= fn << 28;
	cmd.arg |= (write && out) ? 0x08000000 : 0x00000000;
	cmd.arg |= addr << 9;
	cmd.arg |= in;
	cmd.flags = MMC_RSP_SPI_R5 | MMC_RSP_R5 | MMC_CMD_AC;

	err = mmc_wait_for_cmd(host, &cmd, 0);
	if (err)
		return err;

	if (mmc_host_is_spi(host)) {
		/* host driver already reported errors */
	} else {
		if (cmd.resp[0] & R5_ERROR)
			return -EIO;
		if (cmd.resp[0] & R5_FUNCTION_NUMBER)
			return -EINVAL;
		if (cmd.resp[0] & R5_OUT_OF_RANGE)
			return -ERANGE;
	}

	if (out) {
		if (mmc_host_is_spi(host))
			*out = (cmd.resp[0] >> 8) & 0xFF;
		else
			*out = cmd.resp[0] & 0xFF;
	}

	return 0;
}

int mmc_io_rw_direct(struct mmc_card *card, int write, unsigned fn,
	unsigned addr, u8 in, u8 *out)
{
	BUG_ON(!card);
	return mmc_io_rw_direct_host(card->host, write, fn, addr, in, out);
}

void dump_sdio_cccr(struct rtl8192cd_priv *priv)
{
	int i;
	u8 data[0x100];
	
	struct mmc_card *card = priv->pshare->psdio_func->card;
	
	sdio_claim_host(priv->pshare->psdio_func);
	for (i = 0; i < 0x100; ++i) {
		if (mmc_io_rw_direct(card, 0, 0, i, 0, &data[i]))
			break;
	}
	sdio_release_host(priv->pshare->psdio_func);
	
	mem_dump("SDIO CCCR Registers:", data, i);
}

void dump_sdio_local_reg(struct rtl8192cd_priv *priv)
{
#define REG_SZ	0x100

	u8 data[REG_SZ];
	u32 val;
	
	int i, j, len;
	unsigned char tmpbuf[100];
	
	if (sdio_local_read(priv, 0, REG_SZ, data))
		return;
		
	printk(KERN_ERR "SDIO Local Registers:\n");
	
	for (i = 0; i < REG_SZ; i += 0x10) {
		len = sprintf((char *)tmpbuf, "%03X\t", i);
		for (j = i; j < i+0x10; j += 4) {
			val = le32_to_cpup((__le32 *)&data[j]);
			len += sprintf((char *)(tmpbuf+len), "%08X ", val);
		}
		printk(KERN_ERR "%s\n", tmpbuf);
	}
}

void dump_reg(struct rtl8192cd_priv *priv)
{
	int i, j, len;
	unsigned char tmpbuf[100];
	
	printk(KERN_ERR "MAC Registers:\n");
	
	for (i = 0; i < 0x1000; i += 0x10) {
		len = sprintf((char *)tmpbuf, "%03X\t", i);
		for (j = i; j < i+0x10; j += 4)
			len += sprintf((char *)(tmpbuf+len), "%08X ", RTL_R32(j));
		printk(KERN_ERR "%s\n", tmpbuf);
	}
}

