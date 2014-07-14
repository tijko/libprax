#include "prax.h"
#include <stdio.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <limits.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/syscall.h>


int is_alive(profile_t *process)
{
    DIR *proc_dir = opendir(PROC);
    struct dirent *cur_proc = malloc(sizeof *cur_proc);
    while ((cur_proc = readdir(proc_dir))) {
        if (cur_proc->d_type == DT_DIR && 
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

void cpu_affinity(profile_t *process)
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

void setcpu_affinity(profile_t *process, int affinity)
{
    int ret, i;
    cpu_set_t procset;
    size_t procsize;

    CPU_ZERO(&procset);
    for (i=0; i < affinity; CPU_SET(i++, &procset))
        ;
    procsize = sizeof procset;
    
    ret = sched_setaffinity(process->pid, procsize, &procset);
    if (ret == -1) {
        process->cpu_affinity = -1;
    } else {
        process->cpu_affinity = affinity;
    }
}

void process_sid(profile_t *process)
{
    pid_t sid;
    sid = getsid(process->pid);
    process->sid = sid;
}

void rlim_cur(profile_t *process, int resource)
{
    struct rlimit *current = malloc(sizeof *current);
    int ret = prlimit(process->pid, resource, NULL, current);
    if (ret == -1) 
        current->rlim_cur = -1;
    switch (resource) {
        case(RLIMIT_AS): 
            process->addr_space_cur = current->rlim_cur;
            break;
        case(RLIMIT_CORE):
            process->core_cur = current->rlim_cur;
            break;
        case(RLIMIT_CPU):
            process->cpu_cur = current->rlim_cur;
            break;
        case(RLIMIT_DATA):
            process->data_cur = current->rlim_cur;
            break;
        case(RLIMIT_FSIZE):
            process->fsize_cur = current->rlim_cur;
            break;
        case(RLIMIT_LOCKS):
            process->locks_cur = current->rlim_cur;
            break;
        case(RLIMIT_MEMLOCK):
            process->memlock_cur = current->rlim_cur;
            break;
        case(RLIMIT_MSGQUEUE):
            process->msgqueue_cur = current->rlim_cur;
            break;
        case(RLIMIT_NICE):
            process->nice_cur = current->rlim_cur;
            break;
        case(RLIMIT_NOFILE):
            process->nofile_cur = current->rlim_cur;
            break;
        case(RLIMIT_NPROC):
            process->nproc_cur = current->rlim_cur;
            break;
        case(RLIMIT_RSS):
            process->rss_cur = current->rlim_cur;
            break;
        case(RLIMIT_RTPRIO):
            process->rtprio_cur = current->rlim_cur;
            break;
        case(RLIMIT_SIGPENDING):
            process->sigpending_cur = current->rlim_cur;
            break;
        case(RLIMIT_STACK):
            process->stack_cur = current->rlim_cur;
            break;
    }        
}

void rlim_max(profile_t *process, int resource)
{
    struct rlimit *current = malloc(sizeof *current);
    int ret = prlimit(process->pid, resource, NULL, current);
    if (ret == -1) 
        current->rlim_max = -1;
    switch (resource) {
        case(RLIMIT_AS): 
            process->addr_space_max = current->rlim_max;
            break;
        case(RLIMIT_CORE):
            process->core_max = current->rlim_max;
            break;
        case(RLIMIT_CPU):
            process->cpu_max = current->rlim_max;
            break;
        case(RLIMIT_DATA):
            process->data_max = current->rlim_max;
            break;
        case(RLIMIT_FSIZE):
            process->fsize_max = current->rlim_max;
            break;
        case(RLIMIT_LOCKS):
            process->locks_max = current->rlim_max;
            break;
        case(RLIMIT_MEMLOCK):
            process->memlock_max = current->rlim_max;
            break;
        case(RLIMIT_MSGQUEUE):
            process->msgqueue_max = current->rlim_max;
            break;
        case(RLIMIT_NICE):
            process->nice_max = current->rlim_max;
            break;
        case(RLIMIT_NOFILE):
            process->nofile_max = current->rlim_max;
            break;
        case(RLIMIT_NPROC):
            process->nproc_max = current->rlim_max;
            break;
        case(RLIMIT_RSS):
            process->rss_max = current->rlim_max;
            break;
        case(RLIMIT_RTPRIO):
            process->rtprio_max = current->rlim_max;
            break;
        case(RLIMIT_SIGPENDING):
            process->sigpending_max = current->rlim_max;
            break;
        case(RLIMIT_STACK):
            process->stack_max = current->rlim_max;
            break;
    }        
}

void set_rlim(profile_t *process, int resource, unsigned long lim)
{
    int ret;
    struct rlimit *newlim = malloc(sizeof *newlim);
    ret = prlimit(process->pid, resource, NULL, newlim);
    newlim->rlim_cur = lim;
    ret = prlimit(process->pid, resource, newlim, NULL);
    if (ret == -1) 
        lim = 0;
    switch (resource) {
        case(RLIMIT_AS): 
            process->addr_space_cur = lim;
            break;
        case(RLIMIT_CORE):
            process->core_cur = lim;
            break;
        case(RLIMIT_CPU):
            process->cpu_cur = lim;
            break;
        case(RLIMIT_DATA):
            process->data_cur = lim;
            break;
        case(RLIMIT_FSIZE):
            process->fsize_cur = lim;
            break;
        case(RLIMIT_LOCKS):
            process->locks_cur = lim;
            break;
        case(RLIMIT_MEMLOCK):
            process->memlock_cur = lim;
            break;
        case(RLIMIT_MSGQUEUE):
            process->msgqueue_cur = lim;
            break;
        case(RLIMIT_NICE):
            process->nice_cur = lim;
            break;
        case(RLIMIT_NOFILE):
            process->nofile_cur = lim;
            break;
        case(RLIMIT_NPROC):
            process->nproc_cur = lim;
            break;
        case(RLIMIT_RSS):
            process->rss_cur = lim;
            break;
        case(RLIMIT_RTPRIO):
            process->rtprio_cur = lim;
            break;
        case(RLIMIT_SIGPENDING):
            process->sigpending_cur = lim;
            break;
        case(RLIMIT_STACK):
            process->stack_cur = lim;
            break;
    }        
}    
