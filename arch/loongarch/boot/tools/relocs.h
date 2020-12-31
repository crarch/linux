/* SPDX-License-Identifier: GPL-2.0 */
#ifndef RELOCS_H
#define RELOCS_H

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <elf.h>
#include <byteswap.h>
#include <endian.h>
#include <regex.h>

void die(char *fmt, ...);

#ifndef EM_LOONGARCH
#define EM_LOONGARCH	258
#endif
#define R_LARCH_32		1
#define R_LARCH_64		2
#define R_LARCH_MARK_LA		20

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

void process_32(FILE *fp, int as_text, int as_bin,
		int show_reloc_info, int keep_relocs);
void process_64(FILE *fp, int as_text, int as_bin,
		int show_reloc_info, int keep_relocs);

#endif /* RELOCS_H */
