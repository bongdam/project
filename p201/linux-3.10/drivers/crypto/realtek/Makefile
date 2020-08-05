obj-y += crypto_engine/
obj-y += rtl_crypto.o rtl_crypto_helper.o
obj-$(CONFIG_RTK_OPENVPN_HW_CRYPTO) += rtl_openvpn_common.o rtl_fast_openvpn.o
obj-$(CONFIG_REALTEK_CRYPTO_API) += rtl_crypto_api.o

EXTRA_CFLAGS += -I./$(obj) -I./$(obj)/crypto_engine/
