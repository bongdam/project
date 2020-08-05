cmd_rtk_voip/voip_ipc/ipc_arch_viewer := gcc -Wp,-MD,rtk_voip/voip_ipc/.ipc_arch_viewer.d -Wall -Wmissing-prototypes -Wstrict-prototypes -O2 -fomit-frame-pointer   -Irtk_voip/include -Iinclude -include include/linux/kconfig.h  -o rtk_voip/voip_ipc/ipc_arch_viewer rtk_voip/voip_ipc/ipc_arch_viewer.c  

source_rtk_voip/voip_ipc/ipc_arch_viewer := rtk_voip/voip_ipc/ipc_arch_viewer.c

deps_rtk_voip/voip_ipc/ipc_arch_viewer := \
  /usr/include/stdio.h \
  /usr/include/features.h \
  /usr/include/sys/cdefs.h \
  /usr/include/bits/wordsize.h \
  /usr/include/gnu/stubs.h \
  /usr/include/gnu/stubs-32.h \
  /usr/lib/gcc/i386-redhat-linux/4.1.2/include/stddef.h \
  /usr/include/bits/types.h \
  /usr/include/bits/typesizes.h \
  /usr/include/libio.h \
  /usr/include/_G_config.h \
  /usr/include/wchar.h \
  /usr/include/bits/wchar.h \
  /usr/include/gconv.h \
  /usr/lib/gcc/i386-redhat-linux/4.1.2/include/stdarg.h \
  /usr/include/bits/stdio_lim.h \
  /usr/include/bits/sys_errlist.h \
  /usr/include/bits/stdio.h \
  /usr/include/signal.h \
  /usr/include/bits/sigset.h \
  /usr/include/bits/signum.h \
  /usr/include/time.h \
  /usr/include/bits/siginfo.h \
  /usr/include/bits/sigaction.h \
  /usr/include/bits/sigcontext.h \
  /usr/include/asm/sigcontext.h \
  /usr/include/bits/sigstack.h \
  /usr/include/bits/pthreadtypes.h \
  /usr/include/bits/sigthread.h \
  /usr/include/stdlib.h \
  /usr/include/sys/types.h \
  /usr/include/endian.h \
  /usr/include/bits/endian.h \
  /usr/include/sys/select.h \
  /usr/include/bits/select.h \
  /usr/include/bits/time.h \
  /usr/include/sys/sysmacros.h \
  /usr/include/alloca.h \
  /usr/include/netinet/in.h \
  /usr/include/stdint.h \
  /usr/include/sys/socket.h \
  /usr/include/sys/uio.h \
  /usr/include/bits/uio.h \
  /usr/include/bits/socket.h \
  /usr/lib/gcc/i386-redhat-linux/4.1.2/include/limits.h \
  /usr/lib/gcc/i386-redhat-linux/4.1.2/include/syslimits.h \
  /usr/include/limits.h \
  /usr/include/bits/posix1_lim.h \
  /usr/include/bits/local_lim.h \
  /usr/include/linux/limits.h \
  /usr/include/bits/posix2_lim.h \
  /usr/include/bits/sockaddr.h \
  /usr/include/asm/socket.h \
  /usr/include/asm/sockios.h \
  /usr/include/bits/in.h \
  /usr/include/bits/byteswap.h \
  rtk_voip/voip_ipc/ipc_internal.h \
  rtk_voip/include/voip_types.h \
    $(wildcard include/config/rtl865xb.h) \
  rtk_voip/include/voip_ipc.h \
    $(wildcard include/config/rtk/voip/ipc/arch.h) \
  rtk_voip/include/voip_types.h \
  rtk_voip/include/voip_debug.h \

rtk_voip/voip_ipc/ipc_arch_viewer: $(deps_rtk_voip/voip_ipc/ipc_arch_viewer)

$(deps_rtk_voip/voip_ipc/ipc_arch_viewer):
