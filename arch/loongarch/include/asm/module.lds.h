/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020-2021 Loongson Technology Corporation Limited */
SECTIONS {
	. = ALIGN(4);
	.ftrace_tramp : {
		LONG(0); LONG(0); LONG(0); LONG(0);
		LONG(0); LONG(0); LONG(0); LONG(0);
	}
}
