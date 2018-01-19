#pragma once
/*
 *  Copyright (C) 2018 Simon Schmidt
 *
 *	This code is public domain; you can redistribute it and/or modify
 *	it under the terms of the Creative Commons "CC0" license. See LICENSE.CC0
 *	or <http://creativecommons.org/publicdomain/zero/1.0/> for full details.
 *	Alternatively, you can use this software under the terms of the
 *	GNU General Public License version 2, as published by the
 *	Free Software Foundation.
 *
**/
#include <linux/types.h>
#include <linux/cred.h>
#include <linux/capability.h>

typedef struct {
	u32 tetype;
	u32
		in_use: 1,
		deny  : 1,
		rights:30
	;
} MFGAC_aclent_t;

struct MFGAC_task_class {
	kernel_cap_t process_cap_ban;
	u32 secureflags;
	u32 mls_level;
	u32 tasktetype;
	MFGAC_aclent_t acl[16];
};

