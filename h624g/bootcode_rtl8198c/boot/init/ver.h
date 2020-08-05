// version header file
#ifndef __ver_h_
#define __ver_h_

/* v1.5f
    - released with sdk3.4.9.3 in 2015-06-12
   v1.5g
    - patch for booting failure when switch receiving a packets unexpectedly.
    - only utility.c and ver.h are released.
*/

#define B_VERSION "v1.5g";

/* DAVOLINK 14/04/11 young
 * @NOTE: Bootrom version CAN be located at 8 bytes offset from the base of flash.
 * @RULE: MAJOR & MINOR MUST be ranged from '0' to '9'
 *        BUILD MUST be ranged from 'a' to 'z'
 */
#define BT_MAJOR '2'
#define BT_MINOR '0'
#define BT_BUILD 'f'

#define MAKEDWORD(a, b, c, d) ((((a) << 24) & 0xff000000) | (((b) << 16) & 0x00ff0000) | (((c) <<  8) & 0x0000ff00) | ((d)& 0xff))
#endif
