/*
 *  Header files defines some SDIO inline routines
 *
 *  $Id: sdio_io.h,v 1.4.4.5 2010/12/10 06:11:55 family Exp $
 *
 *  Copyright (c) 2009 Realtek Semiconductor Corp.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#ifndef _SDIO_IO_H_
#define _SDIO_IO_H_

u8 sdio_read8(struct rtl8192cd_priv *priv, u32 addr, s32 *err);
u16 sdio_read16(struct rtl8192cd_priv *priv, u32 addr, s32 *err);
u32 sdio_read32(struct rtl8192cd_priv *priv, u32 addr, s32 *err);
s32 sdio_readN(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *pbuf);
s32 sdio_write8(struct rtl8192cd_priv *priv, u32 addr, u8 val);
s32 sdio_write16(struct rtl8192cd_priv *priv, u32 addr, u16 val);
s32 sdio_write32(struct rtl8192cd_priv *priv, u32 addr, u32 val);
s32 sdio_writeN(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8* pbuf);

s32 _sd_read(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, void *pdata);
s32 sd_read(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, void *pdata);
s32 _sd_write(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, void *pdata);
s32 sd_write(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, void *pdata);

u32 sdio_read_port(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *mem);
u32 sdio_write_port(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *mem);

s32 _sdio_local_read(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *pbuf);
s32 sdio_local_read(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *pbuf);
s32 _sdio_local_write(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *pbuf);
s32 sdio_local_write(struct rtl8192cd_priv *priv, u32 addr, u32 cnt, u8 *pbuf);

u8 SdioLocalCmd52Read1Byte(struct rtl8192cd_priv *priv, u32 addr);
u16 SdioLocalCmd52Read2Byte(struct rtl8192cd_priv *priv, u32 addr);
u32 SdioLocalCmd52Read4Byte(struct rtl8192cd_priv *priv, u32 addr);
u32 SdioLocalCmd53Read4Byte(struct rtl8192cd_priv *priv, u32 addr);
void SdioLocalCmd52Write1Byte(struct rtl8192cd_priv *priv, u32 addr, u8 v);
void SdioLocalCmd52Write2Byte(struct rtl8192cd_priv *priv, u32 addr, u16 v);
void SdioLocalCmd52Write4Byte(struct rtl8192cd_priv *priv, u32 addr, u32 v);

void dump_sdio_cccr(struct rtl8192cd_priv *priv);
void dump_sdio_local_reg(struct rtl8192cd_priv *priv);
void dump_reg(struct rtl8192cd_priv *priv);

#endif // _SDIO_IO_H_

