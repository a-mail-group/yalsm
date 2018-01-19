#
# Makefile for the mod_fgac LSM
#

obj-$(CONFIG_SECURITY_MODFGAC) := mod_fgac.o

mod_fgac-y := fgac_lsm.o fgac_device.o

# Classes

mod_fgac-y += task_class.o inode_class.o

# Util
#mod_fgac-y += util_file.o parsenum.o

#mod_fgac-$(CONFIG_SECURITY_MODFGAC_NETFILTER) += dropkin_nf.o

# LSM Hooks.
#mod_fgac-y += sm_tasks.o sm_io.o sm_sysv.o sm_file.o
#mod_fgac-$(CONFIG_SECURITY_NETWORK) += sm_socket.o

