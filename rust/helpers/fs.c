// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2024 Google LLC.
 */

#include <linux/fs.h>

__rust_helper struct file *rust_helper_get_file(struct file *f)
{
	return get_file(f);
}

__rust_helper bool rust_helper_dir_emit(struct dir_context *ctx, const char *name,
					int namelen, u64 ino, unsigned int type)
{
	return dir_emit(ctx, name, namelen, ino, type);
}

__rust_helper void rust_helper_i_size_write(struct inode *inode, loff_t i_size)
{
	i_size_write(inode, i_size);
}

__rust_helper void rust_helper_set_delayed_call(struct delayed_call *call,
						void (*fn)(void *), void *arg)
{
	set_delayed_call(call, fn, arg);
}

__rust_helper kuid_t rust_helper_make_kuid_init_ns(uid_t uid)
{
	return make_kuid(&init_user_ns, uid);
}

__rust_helper kgid_t rust_helper_make_kgid_init_ns(gid_t gid)
{
	return make_kgid(&init_user_ns, gid);
}
