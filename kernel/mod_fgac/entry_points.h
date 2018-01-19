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
#include <linux/lsm_hooks.h>

/* task_class */

int mfgac_cred_alloc_blank(struct cred *cred, gfp_t gfp);
void mfgac_cred_free(struct cred *cred);
int mfgac_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp);
int mfgac_capable(const struct cred *cred, struct user_namespace *ns, int cap, int audit);
int mfgac_task_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

int mfgac_ptrace_access_check(struct task_struct *child, unsigned int mode);
int mfgac_ptrace_traceme(struct task_struct *parent);

/* inode_class */

int  mfgac_inode_alloc_security(struct inode *inode);
void mfgac_inode_free_security(struct inode *inode);
int  mfgac_inode_init_security(
	struct inode *inode,
	struct inode *dir,
	const struct qstr *qstr,
	const char **name,
	void **value,
	size_t *len
);
void mfgac_d_instantiate(struct dentry *dentry, struct inode *inode);
int mfgac_inode_permission(struct inode *inode, int mask);
int mfgac_inode_unlink(struct inode *dir, struct dentry *dentry);
int mfgac_inode_rmdir(struct inode *dir, struct dentry *dentry);
int mfgac_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry);
int mfgac_inode_link(struct dentry *old_dentry, struct inode *dir,struct dentry *new_dentry);
void mfgac_task_to_inode(struct task_struct *p, struct inode *inode);

