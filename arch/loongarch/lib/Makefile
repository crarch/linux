# SPDX-License-Identifier: GPL-2.0
#
# Makefile for LoongArch-specific library files..
#

lib-y	+= delay.o memset.o memcpy.o memmove.o clear_user.o \
	   copy_user.o strncpy_user.o strnlen_user.o csum_partial.o dump_tlb.o

lib-$(CONFIG_GENERIC_CSUM)	:= $(filter-out csum_partial.o, $(lib-y))
