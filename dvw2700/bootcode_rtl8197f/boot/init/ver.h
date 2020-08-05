// version header file
#ifndef __ver_h_
#define __ver_h_

#define B_VERSION "v3.4T-pre2.1"

/* DAVOLINK 18/10/23 young
 * @NOTE: Bootrom version CAN be located at 8 bytes offset from the base of flash.
 * @RULE: MAJOR & MINOR MUST be ranged from '0' to '9'
 *        BUILD MUST be ranged from 'a' to 'z'
 */
#define BT_MAJOR '3'
#define BT_MINOR '5'
#define BT_BUILD 'a'

#define MAKEDWORD(a, b, c, d) ((((a) << 24) & 0xff000000) | (((b) << 16) & 0x00ff0000) | (((c) <<  8) & 0x0000ff00) | ((d)& 0xff))
#endif
