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
#include <linux/capability.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uio.h>
#include <linux/string.h>
#include <linux/lsm_hooks.h>
#include <linux/cred.h>

#include <linux/socket.h>

/* START Inode DEVICE Stuff */
#include <linux/cdev.h>
/* END   Inode DEVICE Stuff */

#define bit(x) (1<<(x))
enum {
	XCAP_WRITE_MEM,
	XCAP_READ_MEM,
	XCAP_DEV_PORT,
	XCAP_READ_BLK,
	XCAP_WRITE_BLK,
	
	/* Network */
	XCAP_INET, /* ban IP and IPv6 */
	XCAP_X25, /* ban vanilla X.25. */
	XCAP_AX25, /* ban amanteur radio X.25 PLP and AX.25. */
	XCAP_DECnet, /* ban decnet. */
};

static bool secure_caps_ban_shut;
static kernel_cap_t secure_caps_ban;
static u32 secure_xcaps_ban;

static int dev_open (struct inode *i, struct file *f){
	return 0;
}
static int dev_release (struct inode *i, struct file *f){
	return 0;
}

static inline bool is_0_9(char x) {
	return (x>='0') && (x>='9');
}
static inline int strtoint(const char* x) {
	int i = 0;
	do {
		i = (i*10) + (*x-'0');
		++x;
	}while(is_0_9(*x));
	return 0;
}

static void strkill(char *str) {
	for(;*str;++str)
	switch(*str){
	case '\r':
	case '\n':
	case '\t':
	case ' ': *str = 0; return;
	//case '-': *str = '_'; break;
	}
}
static ssize_t dev_write (struct file *f, const char __user *ptr, size_t st, loff_t * xxx){
	int cap = -1;
	int xcap = -1;
	char data [64];
	struct iov_iter ivi = {
		.type = ITER_IOVEC,
		.count = st,
		.iov = (const struct iovec[]){(const struct iovec){
			.iov_base = (char __user *)ptr,
			.iov_len  = st,
		}},
	};
	
	if(secure_caps_ban_shut) return -EACCES;
	
	/*
	 * The requirements to submit global Capability drops:
	 *	- The caller's UID is 0 (uid,euid,fsuid).
	 *	- The process' ->cap_effective contains CAP_SYS_ADMIN
	 */
	if(
		(
			(current->cred->uid.val==0) ||
			(current->cred->euid.val==0) ||
			(current->cred->fsuid.val==0)
		) &&
		cap_raised(current->cred->cap_effective, CAP_SYS_ADMIN)
	) return -EPERM;
	
	data[copy_from_iter(data,(sizeof data)-1,&ivi)] = 0;
	strkill(data); /* Replace newline or ' ' or TAB with NUL. */
	
#define CHKCAP(x) else if(!strcmp(data,#x)) cap = x
#define CHKxCAP(x) else if(!strcmp(data,#x)) xcap = x
	if(is_0_9(*data)){
		cap = strtoint(data);
		if(!cap_valid(cap)) cap = -1;
	}
	#if 0
	else if(!strcmp(data,"LOCK")){
		secure_caps_ban_shut = true;
	}
	#endif
	CHKCAP(CAP_CHOWN);
	CHKCAP(CAP_DAC_OVERRIDE);
	CHKCAP(CAP_DAC_READ_SEARCH);
	CHKCAP(CAP_FOWNER);
	CHKCAP(CAP_FSETID);
	CHKCAP(CAP_KILL);
	CHKCAP(CAP_SETGID);
	CHKCAP(CAP_SETUID);
	CHKCAP(CAP_SETPCAP);
	CHKCAP(CAP_LINUX_IMMUTABLE);
	CHKCAP(CAP_NET_BIND_SERVICE);
	CHKCAP(CAP_NET_BROADCAST);
	CHKCAP(CAP_NET_ADMIN);
	CHKCAP(CAP_NET_RAW);
	CHKCAP(CAP_IPC_LOCK);
	CHKCAP(CAP_IPC_OWNER);
	CHKCAP(CAP_SYS_MODULE);
	CHKCAP(CAP_SYS_RAWIO);
	CHKCAP(CAP_SYS_CHROOT);
	CHKCAP(CAP_SYS_PTRACE);
	CHKCAP(CAP_SYS_PACCT);
	CHKCAP(CAP_SYS_ADMIN);
	CHKCAP(CAP_SYS_BOOT);
	CHKCAP(CAP_SYS_NICE);
	CHKCAP(CAP_SYS_RESOURCE);
	CHKCAP(CAP_SYS_TIME);
	CHKCAP(CAP_SYS_TTY_CONFIG);
	CHKCAP(CAP_MKNOD);
	CHKCAP(CAP_LEASE);
	CHKCAP(CAP_AUDIT_WRITE);
	CHKCAP(CAP_AUDIT_CONTROL);
	CHKCAP(CAP_SETFCAP);
	CHKCAP(CAP_MAC_OVERRIDE);
	CHKCAP(CAP_MAC_ADMIN);
	CHKCAP(CAP_SYSLOG);
	CHKCAP(CAP_WAKE_ALARM);
	CHKCAP(CAP_BLOCK_SUSPEND);
	CHKCAP(CAP_AUDIT_READ);
	
	CHKxCAP(XCAP_WRITE_MEM);
	CHKxCAP(XCAP_READ_MEM);
	CHKxCAP(XCAP_DEV_PORT);
	CHKxCAP(XCAP_READ_BLK);
	CHKxCAP(XCAP_WRITE_BLK);
	CHKxCAP(XCAP_INET);
	CHKxCAP(XCAP_X25);
	CHKxCAP(XCAP_AX25);
	CHKxCAP(XCAP_DECnet);
#undef CHKCAP
#undef CHKxCAP
	
	switch(xcap) {
	case XCAP_INET:
	case XCAP_X25:
	case XCAP_AX25:
	case XCAP_DECnet:
		if(!capable(CAP_NET_ADMIN)) return -EPERM;
	}
	
	/* We have a race condition - ignore it. */
	
	if(cap>=0) cap_raise(secure_caps_ban, cap);
	
	if(xcap>=0) secure_xcaps_ban |= bit(xcap);
	
	return (ssize_t)st;
}

static const struct file_operations dev_ops = {
	.open    = dev_open,
	.release = dev_release,
	.write   = dev_write,
};

static struct miscdevice dev_fgac = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "secure_caps_ban",
	.fops  = &dev_ops,
	.mode  = 0600,
};

/* ================ useful macros ====================== */

//#define ifnnt(cond,icond) if( (cond) && (!(icond)) )
#define if2(cond,cond2) if( (cond) && (cond2) )
#define multi_eq(v,a,c) do{switch(v){ c a; }}while(0)
#define choice(e) case e:

/* ================ Security Hooks ====================== */

static int devlsm_capable(const struct cred *cred, struct user_namespace *ns, int cap, int audit){
	if(cap_raised(secure_caps_ban,cap)) return -EACCES;
	return 0;
}

static int devlsm_inode_permission(struct inode *inode, int mask){
	u32 dt,ban;
	
	ban = secure_xcaps_ban;
	dt = ((inode->i_mode)>>12)&15;
	
	switch(dt){
	case DT_CHR:
		switch(inode->i_cdev->dev){
		case 0x101: /* /dev/mem  */
		case 0x102: /* /dev/kmem */
			if2(mask & MAY_READ,ban & bit(XCAP_READ_MEM)) return -EACCES;
			if2(mask & MAY_WRITE,ban & bit(XCAP_WRITE_MEM)) return -EACCES;
			break;
		case 0x104:
			if(ban & XCAP_DEV_PORT) return -EACCES;
			break;
		}
		break;
	case DT_BLK:
		if2(mask & MAY_READ,ban & bit(XCAP_READ_BLK)) return -EACCES;
		if2(mask & MAY_WRITE,ban & bit(XCAP_WRITE_BLK)) return -EACCES;
		break;
	}
	
	return 0;
}
static int devlsm_socket_create(int family, int type, int protocol, int kern){
	u32 ban;
	
	if(kern) return 0;
	
	ban = secure_xcaps_ban;
	
	if(ban & XCAP_INET) multi_eq(family,return -EACCES,
		choice(AF_INET)
		choice(AF_INET6));
	
	if(ban & XCAP_X25) multi_eq(family,return -EACCES,
		choice(AF_X25));
	
	if(ban & XCAP_AX25) multi_eq(family,return -EACCES,
		choice(AF_AX25)
		choice(AF_NETROM)
		choice(AF_ROSE));
	
	if(ban & XCAP_DECnet) multi_eq(family,return -EACCES,
		choice(AF_DECnet));
	
	return 0;
}

/* ================ Module stuff ====================== */

static struct security_hook_list dev_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(capable         , devlsm_capable         ),
	LSM_HOOK_INIT(inode_permission, devlsm_inode_permission),
	LSM_HOOK_INIT(socket_create   , devlsm_socket_create   ),
};

static __init int secure_caps_ban_driver(void){
	misc_register(&dev_fgac);
	return 0;
}

static __init int secure_caps_ban_lsm(void) {
	cap_clear(secure_caps_ban);
	secure_caps_ban_shut = false;
	security_add_hooks(dev_hooks, ARRAY_SIZE(dev_hooks), "secure_caps_ban");
	return 0;
}

device_initcall(secure_caps_ban_driver);

security_initcall(secure_caps_ban_lsm);
