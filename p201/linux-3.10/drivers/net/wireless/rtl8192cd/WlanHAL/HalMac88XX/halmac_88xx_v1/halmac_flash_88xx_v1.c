/******************************************************************************
 *
 * Copyright(c) 2018 - 2019 Realtek Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 ******************************************************************************/

#include "halmac_flash_88xx_v1.h"

#if HALMAC_88XX_V1_SUPPORT

/**
 * download_flash_88xx_v1() -download firmware to flash
 * @adapter : the adapter of halmac
 * @fw_bin : pointer to fw
 * @size : fw size
 * @rom_addr : flash start address where fw should be download
 * Author : Pablo Chiu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
download_flash_88xx_v1(struct halmac_adapter *adapter, u8 *fw_bin, u32 size,
		       u32 rom_addr)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * read_flash_88xx_v1() -read data from flash
 * @adapter : the adapter of halmac
 * @addr : flash start address where fw should be read
 * Author : Pablo Chiu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
read_flash_88xx_v1(struct halmac_adapter *adapter, u32 addr, u32 length,
		   u8 *data)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * erase_flash_88xx_v1() -erase flash data
 * @adapter : the adapter of halmac
 * @erase_cmd : erase command
 * @addr : flash start address where fw should be erased
 * Author : Pablo Chiu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
erase_flash_88xx_v1(struct halmac_adapter *adapter, u8 erase_cmd, u32 addr)
{
	return HALMAC_RET_SUCCESS;
}

/**
 * check_flash_88xx_v1() -check flash data
 * @adapter : the adapter of halmac
 * @fw_bin : pointer to fw
 * @size : fw size
 * @addr : flash start address where fw should be checked
 * Author : Pablo Chiu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
check_flash_88xx_v1(struct halmac_adapter *adapter, u8 *fw_bin, u32 size,
		    u32 addr)
{
	return HALMAC_RET_SUCCESS;
}

#endif /* HALMAC_88XX_V1_SUPPORT */
