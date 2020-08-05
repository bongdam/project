#include "../../../autoconf.h"
#include "i2c/peripheral.h"

void dw_i2c_send_master(u8 bus, u8 addr, u8 data[], int num);
int dw_i2c_read_master(u8 bus, u8 addr, u8 data[], int num);


