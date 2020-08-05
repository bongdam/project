#ifndef	RTL_DAVO_VLAN_H__
#define	RTL_DAVO_VLAN_H__

#define VPORT_CFG_MAX	16
#define VPORT_NUM_MAX	9
#define VPORT_MASK	0x1f	/* Physically Avaiable Port */

extern int wan_vlan_id;

/*
 * Functuion prototype
*/
int vport_read_conf(void);
int vport_apply(void);
void vport_organize_vconf_table(struct rtl865x_vlanConfig *vconfs, int len);

#endif  /*  #ifndef	RTL_DAVO_VLAN_H__   */
