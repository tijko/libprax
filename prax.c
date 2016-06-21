#include "prax.h"

#include <pwd.h>
#include <stdio.h>
#include <ctype.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <limits.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/syscall.h>

#define CONSTRUCT_PATH(path, fmt, parts, ...) asprintf(&path, fmt, __VA_ARGS__)

bool is_alive(profile_t *process)
{
    char *proc_dir_path = malloc(sizeof(char) * PATH_MAX + 1);
    if (!proc_dir_path)
        return false;

    snprintf(proc_dir_path, PATH_MAX, "%s%s", PROC, process->pidstr);
    DIR *proc_dir_handle = opendir(proc_dir_path);
    bool alive = proc_dir_handle ? true : false;

    if (alive)
        closedir(proc_dir_handle);

    free(proc_dir_path);
    return alive;
}

void pid_name(profile_t *process)
{
    if (!is_alive(process)) 
        goto assign_name;

    char *path;
    CONSTRUCT_PATH(path, "%s%s%s", 3, PROC, process->pidstr, COMM);
    FILE *proc = fopen(path, "r");

    char *name = NULL;

    if (proc == NULL) 
        goto free_path;

    size_t n = 0;

    getline(&name, &n, proc);
    fclose(proc);

    name[strlen(name) - 1] = '\0';

free_path:
    free(path);

assign_name:
    process->name = name;

}

static void set_fdstat(char *path, fdstats_t *fdstats)
{
    int open_fd = open(path, O_RDONLY | O_NONBLOCK);

    if (open_fd == -1) 
        return;

    fstat(open_fd, &(fdstats->file_stats));

    close(open_fd);
}

static void set_realpath(char *path, fdstats_t *fdstats)
{
    char realpath[PATH_MAX + 1];

    fdstats->file = NULL;

    if (readlink(path, realpath, PATH_MAX) < 0)
        return;

    realpath[PATH_MAX] = '\0';

    fdstats->file = strdup(realpath);
}

int process_fd_stats(profile_t *process)
{
    struct dirent *files;

    char *fdpath;
    CONSTRUCT_PATH(fdpath, "%s%s%s", 3, PROC, process->pidstr, FD);

    DIR *fd_dir = opendir(fdpath);

    if (!fd_dir) 
        return -1;

    process->fd = malloc(sizeof *(process->fd));
    fdstats_t *curr = process->fd;
    
    while ((files = readdir(fd_dir))) {
        if (files->d_type == DT_LNK) {
 
            char *path;
            CONSTRUCT_PATH(path, "%s%s", 2, fdpath, files->d_name);

            set_fdstat(path, curr);
            set_realpath(path, curr);

            free(path);

            if (!curr->file) 
                continue;

            curr->next_fd = malloc(sizeof *curr->next_fd);

            if (curr->next_fd == NULL)
                break;

            curr = curr->next_fd;
        }
    }

    if (fd_dir)
        closedir(fd_dir);

    free(fdpath);

    return 0;
}

void get_pid_nice(profile_t *process)
{
    int nice = getpriority(PRIO_PROCESS, process->pid);

    if (errno != 0)
        process->nice_err = errno;
    else
        process->nice = nice;
}

void set_pid_nice(profile_t *process, int priority)
{
    int ret = setpriority(PRIO_PROCESS, process->pid, priority);
    if (ret == -1)
        process->nice_err = ret;
    else
        process->nice = priority;
}

void get_ioprio(profile_t *process)
{
    process->ioprio= NULL;

    int ioprio = syscall(GETIOPRIO, IOPRIO_WHO_PROCESS, process->pid);

    if (ioprio == -1)
        return;

    if (IOPRIO_CLASS(ioprio) != 0) {
        process->ioprio = malloc(sizeof(char) * 
                          IOPRIO_LEN(class[IOPRIO_CLASS(ioprio)]));
        snprintf(process->ioprio, IOPRIO_LEN(class[IOPRIO_CLASS(ioprio)]), 
                 "%s%ld", class[IOPRIO_CLASS(ioprio)], IOPRIO_DATA(ioprio));
    } else
        get_ioprio_nice(process, ioprio);
}

void get_ioprio_nice(profile_t *process, int ioprio)
{
    // add check on nice field
    get_pid_nice(process);
    int ioprio_level = (process->nice + 20) / 5;
    int prio = sched_getscheduler(process->pid);

    if (prio == SCHED_FIFO || prio == SCHED_RR) {        
        process->ioprio = malloc(sizeof(char) * IOPRIO_LEN(class[1]));
        snprintf(process->ioprio, IOPRIO_LEN(class[1]), 
                 "%s%d", class[1], ioprio_level);
    } else if (prio == SCHED_OTHER) {
        process->ioprio = malloc(sizeof(char) * IOPRIO_LEN(class[2]));
        snprintf(process->ioprio, IOPRIO_LEN(class[2]), 
                 "%s%d", class[2], ioprio_level);
    } else {
        process->ioprio = malloc(sizeof(char) * strlen(class[3]) + 1);
        snprintf(process->ioprio, IOPRIO_LEN(class[3]), "%s", class[3]);
    }
}

void set_ioprio(profile_t *process, int class, int value)
{
    int ioprio = IOPRIO_VALUE(class, value);
    int setioprio = syscall(SETIOPRIO, IOPRIO_WHO_PROCESS, 
                                     process->pid, ioprio);
    if (setioprio == -1)
        process->ioprio = NULL;
    else
        get_ioprio(process);
}

void cpu_affinity(profile_t *process)
{
    cpu_set_t procset;

    size_t procsize = sizeof procset;
    if (sched_getaffinity(process->pid, procsize, &procset) < 0)
        process->cpu_affinity = -1;
    else 
        process->cpu_affinity = CPU_COUNT(&procset);
}

void setcpu_affinity(profile_t *process, int affinity)
{
    cpu_set_t procset;

    CPU_ZERO(&procset);
    for (int i=0; i < affinity; CPU_SET(i++, &procset))
        ;
    size_t procsize = sizeof procset;
    
    if (sched_setaffinity(process->pid, procsize, &procset) < 0)
        process->cpu_affinity = -1;
    else 
        process->cpu_affinity = affinity;
}

void process_sid(profile_t *process)
{
    pid_t sid = getsid(process->pid);
    process->sid = sid;
}

void rlim_stat(profile_t *process, int resource, unsigned long *lim)
{
    struct rlimit limits;
    prlimit(process->pid, resource, NULL, &limits);

    if (lim) {
        limits.rlim_cur = *lim;
        prlimit(process->pid, resource, &limits, NULL);
    }

    switch (resource) {
        case(RLIMIT_AS): 
            process->addr_space_cur = limits.rlim_cur;
            process->addr_space_max = limits.rlim_max;
            break;
        case(RLIMIT_CORE):
            process->core_cur = limits.rlim_cur;
            process->core_max = limits.rlim_max;
            break;
        case(RLIMIT_CPU):
            process->cpu_cur = limits.rlim_cur;
            process->cpu_max = limits.rlim_max;
            break;
        case(RLIMIT_DATA):
            process->data_cur = limits.rlim_cur;
            process->data_max = limits.rlim_max;
            break;
        case(RLIMIT_FSIZE):
            process->fsize_cur = limits.rlim_cur;
            process->fsize_max = limits.rlim_max;
            break;
        case(RLIMIT_LOCKS):
            process->locks_cur = limits.rlim_cur;
            process->locks_max = limits.rlim_max;
            break;
        case(RLIMIT_MEMLOCK):
            process->memlock_cur = limits.rlim_cur;
            process->memlock_max = limits.rlim_max;
            break;
        case(RLIMIT_MSGQUEUE):
            process->msgqueue_cur = limits.rlim_cur;
            process->msgqueue_max = limits.rlim_max;
            break;
        case(RLIMIT_NICE):
            process->nice_cur = limits.rlim_cur;
            process->nice_max = limits.rlim_max;
            break;
        case(RLIMIT_NOFILE):
            process->nofile_cur = limits.rlim_cur;
            process->nofile_max = limits.rlim_max;
            break;
        case(RLIMIT_NPROC):
            process->nproc_cur = limits.rlim_cur;
            process->nproc_max = limits.rlim_max;
            break;
        case(RLIMIT_RSS):
            process->rss_cur = limits.rlim_cur;
            process->rss_max = limits.rlim_max;
            break;
        case(RLIMIT_RTPRIO):
            process->rtprio_cur = limits.rlim_cur;
            process->rtprio_max = limits.rlim_max;
            break;
        case(RLIMIT_SIGPENDING):
            process->sigpending_cur = limits.rlim_cur;
            process->sigpending_max = limits.rlim_max;
            break;
        case(RLIMIT_STACK):
            process->stack_cur = limits.rlim_cur;
            process->stack_max = limits.rlim_max;
            break;
    }        
}

void running_threads(profile_t *process)
{
    struct dirent *task;
    
    char *path;
    CONSTRUCT_PATH(path, "%s%s%s", 3, PROC, process->pidstr, TASK);

    DIR *task_dir = opendir(path);
    if (task_dir == NULL)
        goto count;
   
    int tid;
    int thread_cnt = 0;
    while ((task = readdir(task_dir))) {
        if (!(ispunct(*(task->d_name)))) {
            tid = atoi(task->d_name);
            process->threads[thread_cnt++] = tid;
        }
    }

    closedir(task_dir);
    
    count:
        process->thread_count = thread_cnt;

    free(path);
}

void tkill(profile_t *process, int tid)
{
    if (syscall(TGKILL, process->tgid, tid, SIGTERM) < 0)
        printf("Thread kill failed :: id - %d\n", tid);
}

static char *parse_status_fields(char *pid, char *field)
{
    char *path;    
    CONSTRUCT_PATH(path, "%s%s%s", 3, PROC, pid, STATUS);

    FILE *fp = fopen(path, "r");
    if (fp == NULL) 
        goto free_path;

    char status[STATUS_SIZE];
    if (fread(status, sizeof(char), STATUS_SIZE - 1, fp) < 0)
        goto close_path;

    char *delimiter = "\n";
    char *field_token = strtok(status, delimiter);

    char *value = NULL;
    while (field_token) {
        if (strstr(field_token, field)) {
            char *value_raw = strchr(field_token, '\t');
            for (; !isdigit(*value_raw); value_raw++);
            value = malloc(sizeof(char) * MAX_FIELD);
            int idx = 0;
            for (; idx < MAX_FIELD - 1 && isdigit(value_raw[idx]); idx++)
                value[idx] = value_raw[idx];
            value[idx] = '\0';
            goto close_path;
        }

        field_token = strtok(NULL, delimiter);
    }

close_path:
    fclose(fp);

free_path:
    free(path);

    return value;
}

static char *parse_stat(char *pid, int field)
{
    char *fieldstr = NULL;
    
    char path[PATH_MAX + 1];
    snprintf(path, PATH_MAX, "%s%s/stat", PROC, pid);

    FILE *fh = fopen(path, "r");
    if (!fh) 
        return NULL;

    size_t n = 0;
    char *line = NULL;
    if (getline(&line, &n, fh) < 0)
        goto close_fh;

    char *delim = " ";
    fieldstr = strtok(line, delim);
    if (!fieldstr || field == 0)
        goto free_line;

    for (int fieldno=0; fieldstr && fieldno < field; fieldno++)
        fieldstr = strtok(NULL, delim);

free_line:
        free(line);
close_fh:
        fclose(fh);

    return strdup(fieldstr);
}

void gettgid(profile_t *process)
{
    char *tgid_name = "Tgid";
    char *tgid = parse_status_fields(process->pidstr, tgid_name); 
    if (tgid) {
        process->tgid = atoi(tgid); 
        free(tgid);
    }
}

void getpuid(profile_t *process)
{
    char *uid_name = "Uid";
    char *uid = parse_status_fields(process->pidstr, uid_name);
    if (uid) {
        process->uid = atoi(uid);
        free(uid);
    }
}

void getusernam(profile_t *process)
{
    if (!process->uid)
        getpuid(process);
    struct passwd *username = getpwuid(process->uid);
    process->username = username->pw_name;
}

void voluntary_context_switches(profile_t *process)
{
    char *vol_switch = "voluntary_ctxt_switches";
    char *vswitch = parse_status_fields(process->pidstr, vol_switch);
    if (vswitch) { 
        process->vol_ctxt_swt = atol(vswitch);
        free(vswitch);
    }
}

void involuntary_context_switches(profile_t *process)
{
    char *invol_switch = "nonvoluntary_ctxt_switches";
    char *ivswitch = parse_status_fields(process->pidstr, invol_switch);
    if (ivswitch) {
        process->invol_ctxt_swt = atol(ivswitch);
        free(ivswitch);
    }
}

void virtual_mem(profile_t *process)
{
    char *virtual_memory = "VmSize";
    char *total_memory = parse_status_fields(process->pidstr, virtual_memory);
    if (total_memory) {
        process->vmem = atol(total_memory);
        free(total_memory);
    }
}

profile_t init_profile(void)
{
    profile_t process = {
        .pidstr = NULL,
        .name = NULL,
        .username = NULL,
        .ioprio = NULL,
        .fd = NULL,
    };

    return process;    
}

void free_profile_fd(profile_t *process)
{
    fdstats_t *curr;
    fdstats_t *next;
    
    for (curr=process->fd; curr; curr=next) {
        next = curr->next_fd;
        free(curr->file);
        free(curr);
    }
}

void free_profile(profile_t *process)
{
    if (!process)
        return;

    if (process->pidstr)
        free(process->pidstr);

    if (process->name)
        free(process->name);

    if (process->ioprio)
        free(process->ioprio);

    if (process->fd)
        free_profile_fd(process);
}
