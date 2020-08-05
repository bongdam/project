obj-y += crypto_engine/
obj-y += rtl_crypto.o rtl_crypto_helper.o
obj-$(CONFIG_RTK_OPENVPN_HW_CRYPTO) += rtl_openvpn_common.o rtl_fast_openvpn.o

EXTRA_CFLAGS += -I./$(obj) -I./$(obj)/crypto_engine/
