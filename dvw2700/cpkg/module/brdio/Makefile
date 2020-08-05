obj-y += brdio.o

$(obj)/brdio.o: $(obj)/rtl8197f_gpio_pinmux_map.c

$(obj)/rtl8197f_gpio_pinmux_map.c: $(obj)/8197f_mux.txt
	@$(obj)/mux2c.sh $(obj)/8197f_mux.txt $@

CFLAGS_brdio.o = -Wall -I$(CPKG_USER)/include -I$(srctree)/drivers/net/rtl819x
