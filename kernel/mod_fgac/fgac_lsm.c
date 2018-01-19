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
#include "entry_points.h"

static struct security_hook_list modfgac_hooks[] __lsm_ro_after_init = {
	/* task_class */
	LSM_HOOK_INIT(cred_alloc_blank    , mfgac_cred_alloc_blank    ),
	LSM_HOOK_INIT(cred_free           , mfgac_cred_free           ),
	LSM_HOOK_INIT(cred_prepare        , mfgac_cred_prepare        ),
	LSM_HOOK_INIT(capable             , mfgac_capable             ),
	LSM_HOOK_INIT(task_prctl          , mfgac_task_prctl          ),
	LSM_HOOK_INIT(ptrace_access_check , mfgac_ptrace_access_check ),
	LSM_HOOK_INIT(ptrace_traceme      , mfgac_ptrace_traceme      ),
	
	
	
	
	/* inode_class */
	LSM_HOOK_INIT(inode_alloc_security, mfgac_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security , mfgac_inode_free_security ),
	LSM_HOOK_INIT(inode_init_security , mfgac_inode_init_security ),
	LSM_HOOK_INIT(d_instantiate       , mfgac_d_instantiate       ),
	LSM_HOOK_INIT(inode_permission    , mfgac_inode_permission    ),
	LSM_HOOK_INIT(inode_unlink        , mfgac_inode_unlink        ),
	LSM_HOOK_INIT(inode_rmdir         , mfgac_inode_rmdir         ),
	LSM_HOOK_INIT(inode_rename        , mfgac_inode_rename        ),
	LSM_HOOK_INIT(inode_link          , mfgac_inode_link          ),
	LSM_HOOK_INIT(task_to_inode       , mfgac_task_to_inode       ),
	
};

static __init int modfgac_init(void) {
	if(!security_module_enable("mod_fgac")) return 0;
	security_add_hooks(modfgac_hooks, ARRAY_SIZE(modfgac_hooks), "mod_fgac");
	return 0;
}

/* Dropkin requires to register LSM hooks. */
security_initcall(modfgac_init);
