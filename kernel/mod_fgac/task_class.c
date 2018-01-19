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
#include <linux/slab.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>
#include <linux/ptrace.h>
#include "task_class.h"
#include "entry_points.h"
#include "inc/xprctl.h"
#include "inc/secureflags.h"
#include "inc/acl.h"

/* =============HOOKS================ */

int mfgac_cred_alloc_blank(struct cred *cred, gfp_t gfp){
	void *x = kzalloc(sizeof(struct MFGAC_task_class),gfp);
	if(!x) return -ENOMEM;
	cred->security = x;
	return 0;
}
void mfgac_cred_free(struct cred *cred){
	struct MFGAC_task_class * tsk = cred->security;
	if(tsk) kfree(tsk);
}
int mfgac_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp){
	struct MFGAC_task_class *nc,*oc;
	nc = kzalloc(sizeof(struct MFGAC_task_class),gfp);
	oc = old->security;
	if(!nc)return -ENOMEM;
	if(!oc)return 0;
	*nc = *oc;
	return 0;
}

int mfgac_capable(const struct cred *cred, struct user_namespace *ns, int cap, int audit){
	struct MFGAC_task_class * tsk = cred->security;
	if(!tsk) return 0;
	if(cap_raised(tsk->process_cap_ban,cap)) return -EACCES;
	return 0;
}


/*  ===== INSERTION ALGORITHM START ====== */
/* match a acl entry against the TEType and the DENY bit */
static inline int my_match(MFGAC_aclent_t acl, u32 t, bool deny) {
	if(!acl.in_use) return 2;
	if(acl.deny&&!deny) return 0;
	if(deny&&!acl.deny) return 0;
	if(acl.tetype != t) return 0;
	return 1;
}

/* Add or Update an entry. Returns false, if there was no space */
static inline bool my_plus(MFGAC_aclent_t* acl, u32 t, u32 rights, bool deny) {
	int i;
	
	for(i=0;i<16;++i)
		switch(my_match(acl[i],t,deny)){
		case 2:
			acl[i].tetype=t;
			acl[i].deny = deny?1:0;
		case 1:
			acl[i].rights |=rights;
			return true;
		}
	
	return false;
}

/*  ===== INSERTION ALGORITHM END ====== */

/*  ===== ACL TRAVERSAL START ====== */

static inline u32 traverse_acl(const u32 tetype,const struct MFGAC_task_class * tsk) {
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
		if(tsk->acl[i].tetype != tetype)continue;
		cur = tsk->acl[i].rights;
		if(tsk->acl[i].deny)deny |= cur; else allow |= cur;
	}
	return allow & ~deny;
}

/*  ===== ACL TRAVERSAL END ====== */

int mfgac_task_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
	struct MFGAC_task_class * tsk = current->cred->security;
	int cap;
	u32 token;
	u32 vec;
	
	if(!tsk) return -ENOSYS;
	
	cap   = arg2;
	token = arg2;
	vec   = arg3;
	
	switch(option){
	case XPR_CAP_BAN:
		cap_raise(tsk->process_cap_ban, cap);
		return 0;
	case XPR_SET_SF:
		tsk->secureflags |= token;
		return 0;
	case XPR_SET_MLS:
		/* Can't raise MLS level, if SF_ENABLE_MLS is enabled. */
		if(tsk->secureflags&SF_ENABLE_MLS) if((tsk->mls_level)<token) return -EACCES;
		/* Must eigher raise or lower the MLS level. */
		if((tsk->mls_level)==token) return 0;
		tsk->mls_level = token;
		return 0;
	case XPR_TE_ALLOW:
		/* If TE is enabled for this process, ALLOWs must not be added anymore. Privilege escalation. */
		if(tsk->secureflags&SF_ENABLE_TE) return -EACCES;
		return my_plus(tsk->acl,token,vec,false)?0: -ENOMEM;
	case XPR_TE_DENY:
		/* Incremental DENYs may be added even with TE enabled. */
		return my_plus(tsk->acl,token,vec,true)?0: -ENOMEM;
	case XPR_TE_SELF:
		/* Lock-Task-TE prevents a task from altering it's own TE-Type. */
		if(tsk->secureflags&SF_LOCK_TASK_TE) return -EACCES;
		tsk->tasktetype = token;
		return 0;
	}
	return -ENOSYS;
}

/* Useful macros for if-statements. */

#define not(x) (!(x))
#define unless(x) if(!(x))

int mfgac_ptrace_access_check(struct task_struct *child, unsigned int mode){
	u32 perm;
	struct MFGAC_task_class *tsk, *ctsk;
	
	/* We are only interested in PTRACE_MODE_REALCREDS mode. */
	if(mode&PTRACE_MODE_FSCREDS) return 0; // XXX: Somehow check this as well?
	
	tsk = current->cred->security;
	ctsk = child->cred->security;
	
	if(!(tsk&&ctsk)) return 0;
	
	/* Impose MLS policy on Ptrace actions! */
	if( (tsk->secureflags & SF_ENABLE_MLS) && (tsk->mls_level<ctsk->mls_level)) return -EACCES;
	
	perm = traverse_acl(ctsk->tasktetype,tsk);
	
	/* Impose TE on ptrace actions! */
	if( (mode & PTRACE_MODE_READ) && not(perm & FPRIV_READ) ) return -EACCES;
	if( (mode & PTRACE_MODE_ATTACH) && not(perm & FPRIV_WRITE) ) return -EACCES;
	
	return 0;
}

int mfgac_ptrace_traceme(struct task_struct *parent){
	u32 perm;
	struct MFGAC_task_class *tsk, *ptsk;
	tsk = current->cred->security;
	ptsk = parent->cred->security;
	
	if(!(tsk&&ptsk)) return 0;
	
	/* Impose MLS policy on Ptrace actions! */
	if( (ptsk->secureflags & SF_ENABLE_MLS) && (ptsk->mls_level<tsk->mls_level)) return -EACCES;
	
	perm = traverse_acl(tsk->tasktetype,ptsk);
	
	/* Impose TE on ptrace actions! */
	unless( perm & (FPRIV_READ|FPRIV_WRITE) ) return -EACCES;
	
	return 0;
}


