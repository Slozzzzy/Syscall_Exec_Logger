#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>

#include "exec_kprobe_core.h"

#define CMDLINE_MAX_LEN 2048

static struct kretprobe exec_kretprobe;

static struct exec_event exec_ring[EXEC_RING_SIZE];
static unsigned int exec_head;      // next write index
static unsigned int exec_count;     // number of valid entries
static spinlock_t exec_lock;

// Push an exec_event into the ring buffer
static void exec_ring_push(const struct exec_event *ev)
{
    unsigned long flags;

    spin_lock_irqsave(&exec_lock, flags);

    exec_ring[exec_head] = *ev;

    exec_head = (exec_head + 1) % EXEC_RING_SIZE;
    if (exec_count < EXEC_RING_SIZE)
        exec_count++;

    spin_unlock_irqrestore(&exec_lock, flags);
}

static int exec_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    long ret;
    struct task_struct *task = current;
    struct mm_struct *mm;
    unsigned long arg_start, arg_end;
    long len;
    char *buf = NULL;
    char *command = NULL;
    char *args = NULL;
    size_t cmd_end;
    int i;

    kuid_t kuid = current_uid();
    uid_t uid   = from_kuid(&init_user_ns, kuid);

    struct timespec64 ts;
    struct exec_event ev;

#if defined(CONFIG_X86_64)
    ret = regs->ax;
#else
    return 0;
#endif

    if (ret < 0) return 0;

    mm = task->mm;
    if (!mm) return 0;

    arg_start = mm->arg_start; // beginning of argv[0]
    arg_end   = mm->arg_end; // end of last arg
    len       = (long)(arg_end - arg_start);

    if (len <= 0) return 0;

    if (len > CMDLINE_MAX_LEN)
        len = CMDLINE_MAX_LEN;

    buf = kmalloc(len + 1, GFP_ATOMIC);
    if (!buf) return 0;

    if (copy_from_user(buf, (const void __user *)arg_start, len) != 0) {
        ktime_get_real_ts64(&ts);
        pr_info("exec kprobe: uid=%u pid=%d - <cmdline_copy_failed> ( %lld.%09ld\n )", uid, task->pid, (long long)ts.tv_sec, ts.tv_nsec);
        kfree(buf);
        return 0;
    }

    buf[len] = '\0';

    cmd_end = strnlen(buf, len); // index of first \0
    command = buf;

    // Check args
    if (cmd_end >= (size_t)len) {
        args = "";
    } else {
        buf[cmd_end] = '\0';

        i = cmd_end + 1;
        if (i >= len) {
            args = "";
        } else {
            int first = i;

            for (; i < len; i++) {
                if (buf[i] == '\0')
                    buf[i] = ' ';
            }

            while (first < len && buf[first] == ' ')
                first++;

            if (first < len && buf[first] != '\0')
                args = &buf[first];
            else
                args = "";
        }
    }

    ktime_get_real_ts64(&ts);

    //Fill exec_event and push into ring buffer
    memset(&ev, 0, sizeof(ev));
    ev.uid = uid;
    ev.pid = task->pid;
    ev.ts  = ts;

    if (command && command[0])
        strscpy(ev.cmd, command, sizeof(ev.cmd));
    else
        strscpy(ev.cmd, "-", sizeof(ev.cmd));

    if (args && args[0])
        strscpy(ev.args, args, sizeof(ev.args));
    else
        strscpy(ev.args, "-", sizeof(ev.args));

    exec_ring_push(&ev);

    /* final log: <uid> <pid> <command> <argument> <time> */
    // pr_info("%u %d %s %s %lld.%09ld\n", uid, task->pid, command[0] ? command : "-", (args && args[0]) ? args : "-", (long long)ts.tv_sec, ts.tv_nsec);
    pr_info("exec kprobe: uid=%u pid=%d %s %s ( %lld.%09ld\n )", uid, task->pid, command[0] ? command : "-", (args && args[0]) ? args : "-", (long long)ts.tv_sec, ts.tv_nsec);
    kfree(buf);
    return 0;
}

int exec_kprobe_core_init(void){
    int ret;

    spin_lock_init(&exec_lock);
    exec_head  = 0;
    exec_count = 0;

    memset(&exec_kretprobe, 0, sizeof(exec_kretprobe));
    exec_kretprobe.kp.symbol_name = "__x64_sys_execve";
    exec_kretprobe.maxactive      = 64;
    exec_kretprobe.handler        = exec_ret_handler;

    ret = register_kretprobe(&exec_kretprobe);
    if (ret < 0) {
        pr_err("exec_kprobe_log: register_kretprobe failed: %d\n", ret);
        return ret;
    }

    pr_info("exec_kprobe_log: kretprobe registered on %s\n",
        exec_kretprobe.kp.symbol_name);
    return ret;
}

void exec_kprobe_core_exit(void){
    unregister_kretprobe(&exec_kretprobe);
    pr_info("exec_kprobe_log: kretprobe unregistered\n");
}
