#ifndef _PE_FW_H_
#define _PE_FW_H_

unsigned long get_pe_fw_virt_addr(void);
unsigned long get_pe_fw_phys_addr(void);
unsigned long get_pe_cpu_virt_addr(void);
unsigned long get_pe_atu_virt_addr(void);
unsigned long get_pe_mem_virt_addr(void);

void set_pe_fw_virt_addr(unsigned long value);
void set_pe_fw_phys_addr(unsigned long value);
void set_pe_cpu_virt_addr(unsigned long value);
void set_pe_atu_virt_addr(unsigned long value);
void set_pe_mem_virt_addr(unsigned long value);

void download_pe_fw(void);
unsigned char check_pe_ready(struct rtl8192cd_priv *priv);

#endif