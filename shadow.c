#include "shadow.h"
#include <stdio.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <limits.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/resource.h>


int is_alive(profile_t *process)
{
    DIR *proc_dir = opendir(PROC);
    struct dirent *cur_proc = malloc(sizeof *cur_proc);
    while ((cur_proc = readdir(proc_dir))) {
        if (cur_proc->d_type ==  DT_DIR && 
            !(strcmp(cur_proc->d_name, process->pidstr))) {
            closedir(proc_dir);
            return 0;
        }
    }
    closedir(proc_dir);
    return -1;
}

char *construct_path(int pathparts, ...)
{
    va_list path;
    va_start(path, pathparts);
    int args;
    size_t pathlen;
    char *part;
    char *partial_path;
    char *pathname = calloc(sizeof(char) * PATH_MAX, sizeof(char));
    for (args=0; args < pathparts; args++) {
        part = va_arg(path, char *);
        pathlen = strlen(part) + strlen(pathname) + 1;
        partial_path = pathname;
        pathname = calloc(sizeof(char) * PATH_MAX, sizeof(char));
        snprintf(pathname, pathlen, "%s%s", partial_path, part);
    }
    va_end(path);
    return pathname;
}

void pid_name(profile_t *process)
{
    int alive = is_alive(process);
    if (alive == -1) {
        process->name = NULL;
    } else {
        char *path = construct_path(3, PROC, process->pidstr, COMM);
        FILE *proc = fopen(path, "r");
        char *name = NULL;
        size_t n = 0;
        getline(&name, &n, proc);
        fclose(proc);
        name[strlen(name) - 1] = '\0';
        process->name = name;
    }
}

int process_fd_stats(profile_t *process)
{
    char *fullpath;
    char *buf;
    int open_fd;
    char *fdpath = construct_path(3, PROC, process->pidstr, FD);

    DIR *fd_dir = opendir(fdpath);
    if (!fd_dir) 
        return -1;

    struct dirent *files = malloc(sizeof *files);

    process->fd = malloc(sizeof *(process->fd));
    fdstats_t *curr = process->fd;
    while ((files = readdir(fd_dir))) {
        if (files->d_type == DT_LNK) {
            fullpath = construct_path(2, fdpath, files->d_name);
            open_fd = open(fullpath, O_RDONLY);
            if (open_fd != -1) {
                buf = calloc(sizeof(char) * LINKBUFSIZ, sizeof(char));
                readlink(fullpath, buf, LINKBUFSIZ);
                curr->file = buf;
                curr->file_stats = malloc(sizeof *(curr->file_stats));
                fstat(open_fd, curr->file_stats);
                curr->next_fd = malloc(sizeof *(curr->next_fd));
                curr = curr->next_fd;
                curr->file = NULL;
            }
            free(fullpath);
        }
    }
    return 0;
}

void get_pid_nice(profile_t *process)
{
    int nice_value;
    nice_value = getpriority(PRIO_PROCESS, process->pid);
    process->nice = nice_value;
}

void set_pid_nice(profile_t *process, int priority)
{
    int ret;
    ret = setpriority(PRIO_PROCESS, process->pid, priority);
    if (ret == -1) {
        process->nice = ret;
    } else {
        process->nice = priority;
    }
}

void get_ioprio(profile_t *process)
{
    int ioprio;
    int ioprio_class_num;
    char *class_name;
    int ioprio_nice;
    size_t priolen;
    char *priority;
    char *ioprio_class[4] = {"none/", "rt/", "be/", "idle/"};
    ioprio = syscall(GETIOPRIO, IOPRIO_WHO_PROCESS, process->pid);
    if (ioprio == -1) { 
        process->io_nice = NULL;
    } else {
        get_pid_nice(process);
        ioprio_class_num = IOPRIO_CLASS(ioprio);
        class_name = ioprio_class[ioprio_class_num];
        ioprio_nice = (process->nice + 20) / 5;
        priolen = strlen(class_name) + IOPRIO_SIZE + 1;
        priority = calloc(priolen, sizeof(char));
        snprintf(priority, priolen, "%s%d", class_name, ioprio_nice);
        process->io_nice = priority;
    }
}

void set_ioprio(profile_t *process, int class, int value)
{
    int ioprio, setioprio;
    ioprio = IOPRIO_VALUE(class, value);
    setioprio = syscall(SETIOPRIO, IOPRIO_WHO_PROCESS, 
                                  process->pid, ioprio);
    if (setioprio == -1) {
        process->io_nice = NULL;
    } else {
        get_ioprio(process);
    }
}

void max_proc_res(profile_t *process, int resource, int *value)
{
    int ret;
    if (value == NULL) {
        struct rlimit *old_limit = malloc(sizeof *old_limit);        
        struct rlimit *new_limit = NULL;
        ret = prlimit(process->pid, resource, new_limit, old_limit);
        if (ret == -1) {
            process->max_res = (unsigned) errno;
        } else {
            process->max_res = (unsigned) old_limit->rlim_max;
        } 
    } else {
        struct rlimit *new_limit = malloc(sizeof *new_limit);
        struct rlimit *old_limit = NULL;
        new_limit->rlim_max = *value;
        ret = prlimit(process->pid, resource, new_limit, old_limit);
        if (ret == -1) {
            process->max_res = (unsigned) errno;
        } else {
            process->max_res = (unsigned) *value;
        }
    }
}

void cur_proc_res(profile_t *process, int resource, int *value)
{
    int ret;
    if (value == NULL) {
        struct rlimit *old_limit = malloc(sizeof *old_limit);        
        struct rlimit *new_limit = NULL;
        ret = prlimit(process->pid, resource, new_limit, old_limit);
        if (ret == -1) {
            process->cur_res = (unsigned) errno;
        } else {
            process->cur_res = (unsigned) old_limit->rlim_cur;
        }
    } else {
        struct rlimit *new_limit = malloc(sizeof *new_limit);
        struct rlimit *old_limit = NULL;
        new_limit->rlim_cur = *value;
        ret = prlimit(process->pid, resource, new_limit, old_limit);
        if (ret == -1) {
            process->cur_res = (unsigned) errno;
        } else {
            process->cur_res = (unsigned) *value;
        }
    }
}

void processor_affinity(profile_t *process)
{
    int ret;
    cpu_set_t procset;
    size_t procsize;

    procsize = sizeof procset;
    ret = sched_getaffinity(process->pid, procsize, &procset);
    if (ret == -1) {
        process->cpu_affinity = -1;
    } else {
        process->cpu_affinity = CPU_COUNT(&procset);
    }
}

void set_processor_affinity(profile_t *process, int cpu_affinity)
{
    int ret, i;
    cpu_set_t procset;
    size_t procsize;

    CPU_ZERO(&procset);
    for (i=0; i < cpu_affinity; CPU_SET(i++, &procset))
        ;
    procsize = sizeof procset;
    
    ret = sched_setaffinity(process->pid, procsize, &procset);
    if (ret == -1) {
        process->cpu_affinity = -1;
    } else {
        process->cpu_affinity = cpu_affinity;
    }
}

void process_sid(profile_t *process)
{
    pid_t sid;
    sid = getsid(process->pid);
    process->sid = sid;
}
