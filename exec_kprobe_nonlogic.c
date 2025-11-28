#include <linux/module.h>
#include <linux/kernel.h>

#include "exec_kprobe_core.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kpakkawat & athanatat");
MODULE_DESCRIPTION("execve kretprobe logging: <uid> <pid> <command> <argument> <time>");
MODULE_VERSION("1.0");

static int __init exec_kprobe_log_init(void)
{
	return exec_kprobe_core_init();
}

static void __exit exec_kprobe_log_exit(void)
{
	exec_kprobe_core_exit();
}

module_init(exec_kprobe_log_init);
module_exit(exec_kprobe_log_exit);

