
//#include <monitor.h>
//#include <rom_def.h>
//#include "../sdcard/sdcard.h"

#include <ddr/efuse.h> //Afooo
#include <rlxboard.h> //Afooo
//#include "../efuse/efuse.h"

/*
#ifndef u1Byte
typedef unsigned char			u1Byte,*pu1Byte;
typedef unsigned short			u2Byte,*pu2Byte;
typedef unsigned int			u4Byte,*pu4Byte;
typedef unsigned long long		u8Byte,*pu8Byte;

typedef signed char				s1Byte,*ps1Byte;
typedef signed short			s2Byte,*ps2Byte;
typedef signed int				s4Byte,*ps4Byte;
typedef signed long long		s8Byte,*ps8Byte;
typedef unsigned long long		ULONG64,*PULONG64;
#endif 
#define PHY_2_NONCACHE_ADDR(addr)   ((addr) | 0x80000000)
#define PHY_2_CACHE_ADDR(addr)      ((addr) | 0xA0000000)
#define CACHE_2_NONCACHE_ADDR(addr) ((addr) | 0x20000000)
#define VIR_2_PHY_ADDR(addr)        ((addr) & (~0xA0000000))

*/



#include "diskio.h"

DSTATUS disk_status (
  BYTE pdrv     /* [IN] Physical drive number */
)
{
    //printf("%s(%d): 0x%x \n", __func__, __LINE__, pdrv);
    return RES_OK;
}

DSTATUS disk_initialize (
  BYTE pdrv           /* [IN] Physical drive number */
)
{
    //printf("%s(%d): 0x%x \n", __func__, __LINE__, pdrv);
    return RES_OK;
}

DRESULT disk_read (
  BYTE pdrv,     /* [IN] Physical drive number */
  BYTE* buff,    /* [OUT] Pointer to the read data buffer */
  DWORD sector,  /* [IN] Start sector number */
  UINT count     /* [IN] Number of sectros to read */
)
{
    unsigned int isWrite = 0; // 1: write, 0: read
    unsigned int start_blk_num;
    unsigned int blk_cnt, ret_val;

    start_blk_num = sector;
    blk_cnt = count;

    //prom_printf(("%s(%d): 0x%x, 0x%x, 0x%x, 0x%x, 0x%x \n", __func__, __LINE__, isWrite, start_blk_num, blk_cnt, &buff[0], VIR_2_PHY_ADDR((u4Byte)&buff[0])));
	ret_val = romcr_sdcard_blk_ops(isWrite, start_blk_num, blk_cnt, (unsigned char*)VIR_2_PHY_ADDR((u4Byte)&buff[0]));

    if (ret_val != 0) {
        //prom_printf(("%s(%d): Error\n", __func__, __LINE__));
    }

    return RES_OK;
}

DRESULT disk_write (
  BYTE pdrv,         /* [IN] Physical drive number */
  const BYTE* buff, /* [IN] Pointer to the data to be written */
  DWORD sector,     /* [IN] Sector number to write from */
  UINT count        /* [IN] Number of sectors to write */
)
{
    //printf("%s(%d): 0x%x, 0x%x, 0x%x, 0x%x \n", __func__, __LINE__, pdrv, buff, sector, count);
    return RES_OK;
}

DRESULT disk_ioctl (
  BYTE pdrv,     /* [IN] Drive number */
  BYTE cmd,      /* [IN] Control command code */
  void* buff     /* [I/O] Parameter and data buffer */
)
{
    //printf("%s(%d): 0x%x, 0x%x, 0x%x \n", __func__, __LINE__, pdrv, cmd, buff);
    return RES_OK;
}

DWORD get_fattime (void)
{
    //printf("%s(%d): \n", __func__, __LINE__);
    return 0;
}


