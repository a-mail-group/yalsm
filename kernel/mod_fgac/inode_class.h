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
//#include "gentypes.h"

#define MFGAC_TYPE_ENF(tp) struct { \
	tp te_itself;\
	tp te_under;\
	tp mls_itself;\
	tp mls_under;\
}

typedef MFGAC_TYPE_ENF(__be32) MFGAC_xattr_t;

struct MFGAC_inode_class {
	MFGAC_TYPE_ENF(u32) subxattr;
	int i;
};


