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
/* for malloc() */
#include <linux/slab.h>

#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/cdev.h>
//#include <linux/capability.h>

#include "entry_points.h"
#include "inode_class.h"
#include "task_class.h"
#include "inc/secureflags.h"
#include "inc/acl.h"

int  mfgac_inode_alloc_security(struct inode *inode) {
	struct MFGAC_inode_class *ins;
	ins = kzalloc(sizeof(struct MFGAC_inode_class),GFP_KERNEL);
	if(!ins)return -ENOMEM;
	inode->i_security = ins;
	return 0;
}

void mfgac_inode_free_security(struct inode *inode) {
	struct MFGAC_inode_class *ins;
	ins = inode->i_security;
	if(ins)kfree(ins);
}

int  mfgac_inode_init_security(
	struct inode *inode,
	struct inode *dir,
	const struct qstr *qstr,
	const char **name,
	void **value,
	size_t *len
) {
	struct MFGAC_inode_class *ins, *drs;
	MFGAC_xattr_t *xattr;
	
	ins = inode->i_security;
	drs = dir->i_security;
	
	if(!(ins&&drs)) return -EOPNOTSUPP;
	
	ins->subxattr.te_under  = ins->subxattr.te_itself  = drs->subxattr.te_under;
	ins->subxattr.mls_under = ins->subxattr.mls_itself = drs->subxattr.mls_under;
	
	if(!(ins->subxattr.te_itself||ins->subxattr.mls_itself)) return -EOPNOTSUPP;
	
	if(name) *name = "MFGAC_TE";
	
	if (value && len) {
		*value = kzalloc(sizeof(MFGAC_xattr_t),GFP_KERNEL);
		if(!*value) return -ENOMEM;
		*len = sizeof(MFGAC_xattr_t);
		xattr = *value;
#define copy_XXX(xxx) xattr->xxx = cpu_to_be32(ins->subxattr.xxx)
		copy_XXX(te_itself);
		copy_XXX(te_under);
		copy_XXX(mls_itself);
		copy_XXX(mls_under);
#undef copy_XXX
	}
	
	return 0;
}

static inline bool is_1(int i) {
	return (i>='1') && (i<='9');
}

void mfgac_d_instantiate(struct dentry *dentry, struct inode *inode) {
	struct MFGAC_inode_class *ins;
	int rc;
	struct dentry *dp;
	union {
		MFGAC_xattr_t xattr;
	} buffer;
	
	ins = inode->i_security;
	
	if(!ins) return;
	
	dp = dget(dentry);
	
	rc = __vfs_getxattr(dp,inode,XATTR_SECURITY_PREFIX "MFGAC_TE",&buffer.xattr,sizeof buffer.xattr);
	if(rc>0){
#define copy_XXX(xxx) ins->subxattr.xxx = be32_to_cpu(buffer.xattr.xxx)
		copy_XXX(te_itself);
		copy_XXX(te_under);
		copy_XXX(mls_itself);
		copy_XXX(mls_under);
#undef copy_XXX
	}
	
	dput(dp);
}

static inline u32 traverse_acl(const struct MFGAC_inode_class *ins,const struct MFGAC_task_class * tsk) {
	register int i;
	register u32 allow,deny,cur;
	
	/* By default, set every bit! */
	allow = ~((u32)0);
	deny  = 0;
	if(tsk->secureflags & SF_ENABLE_TE) {
		allow = 0;
	}
	
	for(i=0;i<16;++i){
		if(!(tsk->acl[i].in_use))continue;
		if(tsk->acl[i].tetype!=ins->subxattr.te_itself)continue;
		cur = tsk->acl[i].rights;
		if(tsk->acl[i].deny)deny |= cur; else allow |= cur;
	}
	return allow & ~deny;
}

enum {
	M2_DELETE     = 1,
	M2_INV_APPEND = 2, /* The inverse of append - delete file from directory. */
	M2_LINK       = 4, /* Create a link. */
};
#define _or ?:
#define _cond(a,b) ((a)?(b):0)
static int inode_generic(struct inode *inode, int mask,int mask2) {
	u32 perm;
	struct MFGAC_inode_class *ins;
	struct MFGAC_task_class * tsk = current->cred->security;
	
	ins = inode->i_security;
	
	if(!(ins&&tsk)) return 0;
	
	if(tsk->secureflags & SF_ENABLE_MLS){
		/* if SecLevel(subject) > SecLevel(object), then DENY. */
		if((ins->subxattr.mls_itself) > (tsk->mls_level)) return -EACCES;
	}
	
	perm = traverse_acl(ins,tsk);
	if((mask&MAY_EXEC  ) && !(perm&FPRIV_EXEC  )) return -EACCES;
	if((mask&MAY_WRITE ) && !(perm&FPRIV_WRITE )) return -EACCES;
	if((mask&MAY_READ  ) && !(perm&FPRIV_READ  )) return -EACCES;
	if((mask&MAY_APPEND) && !(perm&(FPRIV_APPEND|FPRIV_WRITE))) return -EACCES;
	
	if((mask2&M2_INV_APPEND) && !(perm&FPRIV_WRITE)) return -EACCES;
	if((mask2&M2_DELETE) && !(perm&FPRIV_DELETE)) return -EACCES;
	
	return 0;
}

int mfgac_inode_permission(struct inode *inode, int mask) {
	return inode_generic(inode,mask,0);
}

int mfgac_inode_unlink(struct inode *dir, struct dentry *dentry) {
	struct inode *inode;
	
	inode = dentry->d_inode;
	
	return inode_generic(dir,0,M2_INV_APPEND) _or _cond(inode,inode_generic(inode,0,M2_DELETE));
}

int mfgac_inode_rmdir(struct inode *dir, struct dentry *dentry){
	return mfgac_inode_unlink(dir,dentry);
}
int mfgac_inode_link(struct dentry *old_dentry, struct inode *dir,struct dentry *new_dentry){
	struct inode *ofile,*nfile;
	
	ofile = old_dentry->d_inode;
	nfile = new_dentry->d_inode;
	
	return inode_generic(dir,MAY_APPEND,_cond(nfile,M2_INV_APPEND))
	_or _cond(nfile,inode_generic(nfile,0,M2_DELETE));
}
int mfgac_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry){
	struct inode *ofile,*nfile;
	
	ofile = old_dentry->d_inode;
	nfile = new_dentry->d_inode;
	
	return inode_generic(old_dir,0,M2_INV_APPEND) _or inode_generic(new_dir,MAY_APPEND,_cond(nfile,M2_INV_APPEND))
	_or _cond(ofile,inode_generic(ofile,0,M2_DELETE))
	_or _cond(nfile,inode_generic(nfile,0,M2_DELETE));
}

void mfgac_task_to_inode(struct task_struct *p, struct inode *inode) {
	struct MFGAC_inode_class *ins;
	struct MFGAC_task_class * tsk;
	ins = inode->i_security;
	tsk = p->cred->security;
	
	if(!(ins&&tsk)) return;
	
	ins->subxattr.mls_itself = tsk->mls_level;
	ins->subxattr.te_itself  = tsk->tasktetype;
	ins->subxattr.mls_under  = ins->subxattr.mls_itself;
	ins->subxattr.te_under   = ins->subxattr.te_itself;
}

