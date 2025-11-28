#ifndef EXEC_KPROBE_CORE_H
#define EXEC_KPROBE_CORE_H
#include <linux/types.h>
#include <linux/time64.h>

#define EXEC_RING_SIZE   1024
#define EXEC_STR_MAX     256
#define EXEC_ARGS_MAX    512

struct exec_event {
    struct timespec64 ts;
    uid_t           uid;
    pid_t           pid;
    char            cmd[EXEC_STR_MAX];
    char            args[EXEC_ARGS_MAX];
};

int exec_kprobe_core_init(void);

void exec_kprobe_core_exit(void);

#endif
