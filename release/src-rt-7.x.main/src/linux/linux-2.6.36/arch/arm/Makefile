#
# arch/arm/Makefile
#
# This file is included by the global makefile so that you can add your own
# architecture-specific flags and dependencies.
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Copyright (C) 1995-2001 by Russell King

LDFLAGS_vmlinux	:=-p --no-undefined -X
ifeq ($(CONFIG_CPU_ENDIAN_BE8),y)
LDFLAGS_vmlinux	+= --be8
endif

OBJCOPYFLAGS	:=-O binary -R .note -R .note.gnu.build-id -R .comment -S
GZFLAGS		:=-9
#KBUILD_CFLAGS	+=-pipe
# Explicitly specifiy 32-bit ARM ISA since toolchain default can be -mthumb:
KBUILD_CFLAGS	+=$(call cc-option,-marm,)
KBUILD_CFLAGS	+=$(call cc-option,-ffreestanding,)

# Never generate .eh_frame
KBUILD_CFLAGS	+= $(call cc-option,-fno-dwarf2-cfi-asm)

# Do not use arch/arm/defconfig - it's always outdated.
# Select a platform tht is kept up-to-date
KBUILD_DEFCONFIG := versatile_defconfig

# defines filename extension depending memory management type.
ifeq ($(CONFIG_MMU),)
MMUEXT		:= -nommu
endif

ifeq ($(CONFIG_FRAME_POINTER),y)
KBUILD_CFLAGS	+=-fno-omit-frame-pointer -mapcs -mno-sched-prolog
endif

ifeq ($(CONFIG_CC_STACKPROTECTOR),y)
KBUILD_CFLAGS	+=-fstack-protector
endif

ifeq ($(CONFIG_CPU_BIG_ENDIAN),y)
KBUILD_CPPFLAGS	+= -mbig-endian
AS		+= -EB
LD		+= -EB
else
KBUILD_CPPFLAGS	+= -mlittle-endian
AS		+= -EL
LD		+= -EL
endif

comma = ,

# This selects which instruction set is used.
# Note that GCC does not numerically define an architecture version
# macro, but instead defines a whole series of macros which makes
# testing for a specific architecture or later rather impossible.
arch-$(CONFIG_CPU_32v7)		:=-D__LINUX_ARM_ARCH__=7 $(call cc-option,-march=armv7-a -mtune=cortex-a9,-march=armv5t -Wa$(comma)-march=armv7-a)
arch-$(CONFIG_CPU_32v6)		:=-D__LINUX_ARM_ARCH__=6 $(call cc-option,-march=armv6,-march=armv5t -Wa$(comma)-march=armv6)
# Only override the compiler option if ARMv6. The ARMv6K extensions are
# always available in ARMv7
ifeq ($(CONFIG_CPU_32v6),y)
arch-$(CONFIG_CPU_32v6K)	:=-D__LINUX_ARM_ARCH__=6 $(call cc-option,-march=armv6k,-march=armv5t -Wa$(comma)-march=armv6k)
endif
arch-$(CONFIG_CPU_32v5)		:=-D__LINUX_ARM_ARCH__=5 $(call cc-option,-march=armv5te,-march=armv4t)
arch-$(CONFIG_CPU_32v4T)	:=-D__LINUX_ARM_ARCH__=4 -march=armv4t
arch-$(CONFIG_CPU_32v4)		:=-D__LINUX_ARM_ARCH__=4 -march=armv4
arch-$(CONFIG_CPU_32v3)		:=-D__LINUX_ARM_ARCH__=3 -march=armv3

# This selects how we optimise for the processor.
tune-$(CONFIG_CPU_ARM610)	:=-mtune=arm610
tune-$(CONFIG_CPU_ARM710)	:=-mtune=arm710
tune-$(CONFIG_CPU_ARM7TDMI)	:=-mtune=arm7tdmi
tune-$(CONFIG_CPU_ARM720T)	:=-mtune=arm7tdmi
tune-$(CONFIG_CPU_ARM740T)	:=-mtune=arm7tdmi
tune-$(CONFIG_CPU_ARM9TDMI)	:=-mtune=arm9tdmi
tune-$(CONFIG_CPU_ARM940T)	:=-mtune=arm9tdmi
tune-$(CONFIG_CPU_ARM946E)	:=$(call cc-option,-mtune=arm9e,-mtune=arm9tdmi)
tune-$(CONFIG_CPU_ARM920T)	:=-mtune=arm9tdmi
tune-$(CONFIG_CPU_ARM922T)	:=-mtune=arm9tdmi
tune-$(CONFIG_CPU_ARM925T)	:=-mtune=arm9tdmi
tune-$(CONFIG_CPU_ARM926T)	:=-mtune=arm9tdmi
tune-$(CONFIG_CPU_FA526)	:=-mtune=arm9tdmi
tune-$(CONFIG_CPU_SA110)	:=-mtune=strongarm110
tune-$(CONFIG_CPU_SA1100)	:=-mtune=strongarm1100
tune-$(CONFIG_CPU_XSCALE)	:=$(call cc-option,-mtune=xscale,-mtune=strongarm110) -Wa,-mcpu=xscale
tune-$(CONFIG_CPU_XSC3)		:=$(call cc-option,-mtune=xscale,-mtune=strongarm110) -Wa,-mcpu=xscale
tune-$(CONFIG_CPU_FEROCEON)	:=$(call cc-option,-mtune=marvell-f,-mtune=xscale)
tune-$(CONFIG_CPU_V6)		:=$(call cc-option,-mtune=arm1136j-s,-mtune=strongarm)

ifeq ($(CONFIG_AEABI),y)
CFLAGS_ABI	:=-mabi=aapcs-linux -mno-thumb-interwork
else
CFLAGS_ABI	:=$(call cc-option,-mapcs-32,-mabi=apcs-gnu) $(call cc-option,-mno-thumb-interwork,)
endif

ifeq ($(CONFIG_ARM_UNWIND),y)
CFLAGS_ABI	+=-funwind-tables
endif

ifeq ($(CONFIG_THUMB2_KERNEL),y)
AFLAGS_AUTOIT	:=$(call as-option,-Wa$(comma)-mimplicit-it=always,-Wa$(comma)-mauto-it)
AFLAGS_NOWARN	:=$(call as-option,-Wa$(comma)-mno-warn-deprecated,-Wa$(comma)-W)
CFLAGS_THUMB2	:=-mthumb $(AFLAGS_AUTOIT) $(AFLAGS_NOWARN)
AFLAGS_THUMB2	:=$(CFLAGS_THUMB2) -Wa$(comma)-mthumb
endif

# Need -Uarm for gcc < 3.x
KBUILD_CFLAGS	+=$(CFLAGS_ABI) $(CFLAGS_THUMB2) $(arch-y) $(tune-y) $(call cc-option,-mshort-load-bytes,$(call cc-option,-malignment-traps,)) -msoft-float -Uarm
KBUILD_AFLAGS	+=$(CFLAGS_ABI) $(AFLAGS_THUMB2) $(arch-y) $(tune-y) -include asm/unified.h -msoft-float

# Always compile with debug symbols. They will be stripped by the router
# makefile to produce the final kernel. Debug versions of kernel and brcm
# kernel modules will be kept with the extension dbgsym attached to their
# names.
KBUILD_CFLAGS += -ggdb

CHECKFLAGS	+= -D__arm__

#Default value
head-y		:= arch/arm/kernel/head$(MMUEXT).o arch/arm/kernel/init_task.o
textofs-y	:= 0x00008000
textofs-$(CONFIG_ARCH_CLPS711X) := 0x00028000
# We don't want the htc bootloader to corrupt kernel during resume
textofs-$(CONFIG_PM_H1940)      := 0x00108000
# SA1111 DMA bug: we don't want the kernel to live in precious DMA-able memory
ifeq ($(CONFIG_ARCH_SA1100),y)
textofs-$(CONFIG_SA1111) := 0x00208000
endif
# Kona u-Boot reserves memory below this address, and puts tags here
ifeq ($(CONFIG_MACH_BRCM_GEN),y)
textofs-$(CONFIG_MACH_BRCM_GEN) := 0x00208000
endif

# Machine directory name.  This list is sorted alphanumerically
# by CONFIG_* macro name.
machine-$(CONFIG_ARCH_AAEC2000)		:= aaec2000
machine-$(CONFIG_ARCH_AT91)		:= at91
machine-$(CONFIG_ARCH_BCMRING)		:= bcmring
machine-$(CONFIG_ARCH_CLPS711X)		:= clps711x
machine-$(CONFIG_ARCH_CNS3XXX)		:= cns3xxx
machine-$(CONFIG_ARCH_DAVINCI)		:= davinci
machine-$(CONFIG_ARCH_DOVE)		:= dove
machine-$(CONFIG_ARCH_EBSA110)		:= ebsa110
machine-$(CONFIG_ARCH_EP93XX)		:= ep93xx
machine-$(CONFIG_ARCH_GEMINI)		:= gemini
machine-$(CONFIG_ARCH_H720X)		:= h720x
machine-$(CONFIG_ARCH_INTEGRATOR)	:= integrator
machine-$(CONFIG_ARCH_IOP13XX)		:= iop13xx
machine-$(CONFIG_ARCH_IOP32X)		:= iop32x
machine-$(CONFIG_ARCH_IOP33X)		:= iop33x
machine-$(CONFIG_ARCH_IXP2000)		:= ixp2000
machine-$(CONFIG_ARCH_IXP23XX)		:= ixp23xx
machine-$(CONFIG_ARCH_IXP4XX)		:= ixp4xx
machine-$(CONFIG_ARCH_KIRKWOOD)		:= kirkwood
machine-$(CONFIG_ARCH_KS8695)		:= ks8695
machine-$(CONFIG_ARCH_LH7A40X)		:= lh7a40x
machine-$(CONFIG_ARCH_LOKI) 		:= loki
machine-$(CONFIG_ARCH_LPC32XX)		:= lpc32xx
machine-$(CONFIG_ARCH_MMP)		:= mmp
machine-$(CONFIG_ARCH_MSM)		:= msm
machine-$(CONFIG_ARCH_MV78XX0)		:= mv78xx0
machine-$(CONFIG_ARCH_MX1)		:= imx
machine-$(CONFIG_ARCH_MX2)		:= imx
machine-$(CONFIG_ARCH_MX25)		:= mx25
machine-$(CONFIG_ARCH_MX3)		:= mx3
machine-$(CONFIG_ARCH_MX5)		:= mx5
machine-$(CONFIG_ARCH_MXC91231)		:= mxc91231
machine-$(CONFIG_ARCH_NETX)		:= netx
machine-$(CONFIG_ARCH_NOMADIK)		:= nomadik
machine-$(CONFIG_ARCH_NS9XXX)		:= ns9xxx
machine-$(CONFIG_ARCH_OMAP1)		:= omap1
machine-$(CONFIG_ARCH_OMAP2)		:= omap2
machine-$(CONFIG_ARCH_OMAP3)		:= omap2
machine-$(CONFIG_ARCH_OMAP4)		:= omap2
machine-$(CONFIG_ARCH_ORION5X)		:= orion5x
machine-$(CONFIG_ARCH_PNX4008)		:= pnx4008
machine-$(CONFIG_ARCH_PXA)		:= pxa
machine-$(CONFIG_ARCH_REALVIEW)		:= realview
machine-$(CONFIG_ARCH_RPC)		:= rpc
machine-$(CONFIG_ARCH_S3C2410)		:= s3c2410 s3c2400 s3c2412 s3c2416 s3c2440 s3c2443
machine-$(CONFIG_ARCH_S3C24A0)		:= s3c24a0
machine-$(CONFIG_ARCH_S3C64XX)		:= s3c64xx
machine-$(CONFIG_ARCH_S5P6440)		:= s5p6440
machine-$(CONFIG_ARCH_S5P6442)		:= s5p6442
machine-$(CONFIG_ARCH_S5PC100)		:= s5pc100
machine-$(CONFIG_ARCH_S5PV210)		:= s5pv210
machine-$(CONFIG_ARCH_S5PV310)		:= s5pv310
machine-$(CONFIG_ARCH_SA1100)		:= sa1100
machine-$(CONFIG_ARCH_SHARK)		:= shark
machine-$(CONFIG_ARCH_SHMOBILE) 	:= shmobile
machine-$(CONFIG_ARCH_STMP378X)		:= stmp378x
machine-$(CONFIG_ARCH_STMP37XX)		:= stmp37xx
machine-$(CONFIG_ARCH_TEGRA)		:= tegra
machine-$(CONFIG_ARCH_U300)		:= u300
machine-$(CONFIG_ARCH_U8500)		:= ux500
machine-$(CONFIG_ARCH_VERSATILE)	:= versatile
machine-$(CONFIG_ARCH_VEXPRESS)		:= vexpress
machine-$(CONFIG_ARCH_W90X900)		:= w90x900
machine-$(CONFIG_ARCH_NUC93X)		:= nuc93x
machine-$(CONFIG_FOOTBRIDGE)		:= footbridge
machine-$(CONFIG_MACH_SPEAR300)		:= spear3xx
machine-$(CONFIG_MACH_SPEAR310)		:= spear3xx
machine-$(CONFIG_MACH_SPEAR320)		:= spear3xx
machine-$(CONFIG_MACH_SPEAR600)		:= spear6xx
machine-$(CONFIG_ARCH_BRCM)		:= brcm-hnd

# Platform directory name.  This list is sorted alphanumerically
# by CONFIG_* macro name.
plat-$(CONFIG_ARCH_MXC)		:= mxc
plat-$(CONFIG_ARCH_OMAP)	:= omap
plat-$(CONFIG_ARCH_S3C64XX)	:= samsung
plat-$(CONFIG_ARCH_STMP3XXX)	:= stmp3xxx
plat-$(CONFIG_PLAT_IOP)		:= iop
plat-$(CONFIG_PLAT_MPCORE)	:= brcm
plat-$(CONFIG_PLAT_IPROC)	:= brcm
plat-$(CONFIG_PLAT_NOMADIK)	:= nomadik
plat-$(CONFIG_PLAT_ORION)	:= orion
plat-$(CONFIG_PLAT_PXA)		:= pxa
plat-$(CONFIG_PLAT_S3C24XX)	:= s3c24xx samsung
plat-$(CONFIG_PLAT_S5P)		:= s5p samsung
plat-$(CONFIG_PLAT_SPEAR)	:= spear
plat-$(CONFIG_PLAT_VERSATILE)	:= versatile

ifeq ($(CONFIG_ARCH_EBSA110),y)
# This is what happens if you forget the IOCS16 line.
# PCMCIA cards stop working.
CFLAGS_3c589_cs.o :=-DISA_SIXTEEN_BIT_PERIPHERAL
export CFLAGS_3c589_cs.o
endif

# The byte offset of the kernel image in RAM from the start of RAM.
TEXT_OFFSET := $(textofs-y)

# The first directory contains additional information for the boot setup code
ifneq ($(machine-y),)
MACHINE  := arch/arm/mach-$(word 1,$(machine-y))/
else
MACHINE  :=
endif

machdirs := $(patsubst %,arch/arm/mach-%/,$(machine-y))
platdirs := $(patsubst %,arch/arm/plat-%/,$(plat-y))

ifeq ($(KBUILD_SRC),)
KBUILD_CPPFLAGS += $(patsubst %,-I%include,$(machdirs) $(platdirs))
else
KBUILD_CPPFLAGS += $(patsubst %,-I$(srctree)/%include,$(machdirs) $(platdirs))
endif

export	TEXT_OFFSET GZFLAGS MMUEXT

# Do we have FASTFPE?
FASTFPE		:=arch/arm/fastfpe
ifeq ($(FASTFPE),$(wildcard $(FASTFPE)))
FASTFPE_OBJ	:=$(FASTFPE)/
endif

# If we have a machine-specific directory, then include it in the build.
core-y				+= arch/arm/kernel/ arch/arm/mm/ arch/arm/common/
core-y				+= $(machdirs) $(platdirs)
core-$(CONFIG_FPE_NWFPE)	+= arch/arm/nwfpe/
core-$(CONFIG_FPE_FASTFPE)	+= $(FASTFPE_OBJ)
core-$(CONFIG_VFP)		+= arch/arm/vfp/

drivers-$(CONFIG_OPROFILE)      += arch/arm/oprofile/

libs-y				:= arch/arm/lib/ $(libs-y)

# Default target when executing plain make
ifeq ($(CONFIG_XIP_KERNEL),y)
KBUILD_IMAGE := xipImage
else
KBUILD_IMAGE := zImage
endif

all:	$(KBUILD_IMAGE)

boot := arch/arm/boot

archprepare:
	$(Q)$(MAKE) $(build)=arch/arm/tools include/generated/mach-types.h

# Convert bzImage to zImage
bzImage: zImage

zImage Image xipImage bootpImage uImage: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) MACHINE=$(MACHINE) $(boot)/$@

zinstall install: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) MACHINE=$(MACHINE) $@

# We use MRPROPER_FILES and CLEAN_FILES now
archclean:
	$(Q)$(MAKE) $(clean)=$(boot)

# My testing targets (bypasses dependencies)
bp:;	$(Q)$(MAKE) $(build)=$(boot) MACHINE=$(MACHINE) $(boot)/bootpImage
i zi:;	$(Q)$(MAKE) $(build)=$(boot) MACHINE=$(MACHINE) $@


define archhelp
  echo  '* zImage        - Compressed kernel image (arch/$(ARCH)/boot/zImage)'
  echo  '  Image         - Uncompressed kernel image (arch/$(ARCH)/boot/Image)'
  echo  '* xipImage      - XIP kernel image, if configured (arch/$(ARCH)/boot/xipImage)'
  echo  '  uImage        - U-Boot wrapped zImage'
  echo  '  bootpImage    - Combined zImage and initial RAM disk' 
  echo  '                  (supply initrd image via make variable INITRD=<path>)'
  echo  '  install       - Install uncompressed kernel'
  echo  '  zinstall      - Install compressed kernel'
  echo  '                  Install using (your) ~/bin/$(INSTALLKERNEL) or'
  echo  '                  (distribution) /sbin/$(INSTALLKERNEL) or'
  echo  '                  install to $$(INSTALL_PATH) and run lilo'
endef
