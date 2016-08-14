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
#include <sys/socket.h>
#include <sys/syscall.h>

#define CONSTRUCT_PATH(path, fmt, parts, ...) asprintf(&path, fmt, __VA_ARGS__)

bool is_alive(profile_t *process)
{
    char proc_dir_path[PATH_MAX + 1];

    snprintf(proc_dir_path, PATH_MAX, "%s%s", PROC, process->pidstr);
    DIR *proc_dir_handle = opendir(proc_dir_path);
    bool alive = proc_dir_handle ? true : false;

    if (alive)
        closedir(proc_dir_handle);

    return alive;
}

static void *parse_taskmsg(int req, struct taskmsg *msg)
{
    int msglength = msg->nl.nlmsg_len;

    msglength -= (NLMSG_HDRLEN + GENL_HDRLEN);
    struct nlattr *nla = GENLMSG_DATA(msg->gnl);
    int nla_msg_len = 0;

    while (msglength > 0) {
        if (nla->nla_type == req)
            return (void *) ((char *) nla + NLA_HDRLEN);
        else if (nla->nla_type == TASKSTATS_TYPE_AGGR_PID) {
            nla_msg_len = NLA_HDRLEN;
            msglength -= nla_msg_len;
        } else {
            nla_msg_len = NLMSG_ALIGN(nla->nla_len);
            msglength -= nla->nla_len;
        }

        nla = (struct nlattr *) ((char *) nla + nla_msg_len);        
    }

    return NULL;
}

static int create_nl_conn(void)
{
    int nl_conn = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);

    if (nl_conn < 0)
        return -1;

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof addr);

    addr.nl_family = AF_NETLINK;

    if (bind(nl_conn, (struct sockaddr *) &addr, sizeof addr) < 0)
        return -1;

    return nl_conn;
}

static inline void build_req(struct taskmsg *msg, int nl_type, int cmd,
                        int nla_type, int nla_data_len, void *nla_data)
{
    msg->nl.nlmsg_flags = NLM_F_REQUEST;
    msg->nl.nlmsg_type = nl_type;
    msg->nl.nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN;

    msg->gnl.version = 0x1;
    msg->gnl.cmd = cmd;

    struct nlattr *nla = GENLMSG_DATA(msg->gnl);
    nla->nla_type = nla_type;
    nla->nla_len = NLA_HDRLEN + nla_data_len;
    msg->nl.nlmsg_len += NLMSG_ALIGN(nla->nla_len);
    memcpy(NLA_DATA(nla), nla_data, nla_data_len); 
}
 
static int recv_nl_req(int conn, struct taskmsg *msg)
{
    int bytes_recv = recv(conn, msg, sizeof *msg, 0);

    if (bytes_recv < 0)
        return -1;

    return 0;
}

static void *make_nl_req(int req, profile_t *process)
{
    struct taskmsg msg;
    memset(&msg, 0, sizeof msg);

    int data_len;

    switch (req) {

        case (CTRL_CMD_GETFAMILY):
            data_len = strlen(TASKSTATS_GENL_NAME) + 1;
            build_req(&msg, GENL_ID_CTRL, req, CTRL_ATTR_FAMILY_NAME,
                       data_len, TASKSTATS_GENL_NAME);
            break;
        case (TASKSTATS_CMD_GET):
            build_req(&msg, process->nl_family_id, req,
                TASKSTATS_CMD_ATTR_PID, sizeof(int), &(process->pid));
            break;

    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof addr);
    addr.nl_family = AF_NETLINK;

    int msglength = msg.nl.nlmsg_len;
    char *msg_buffer = (char *) &msg;

    while (msglength > 0) {
        int bytes_sent = sendto(process->nl_conn, msg_buffer, msglength, 0,
                            (struct sockaddr *) &addr, sizeof addr);
        if (bytes_sent < 0)
            return NULL;
        msglength -= bytes_sent;
        msg_buffer += bytes_sent;
    }

    memset(&msg, 0, sizeof msg);
    if (recv_nl_req(process->nl_conn, &msg) < 0)
        return NULL;

    void *task_ret = NULL;

    if (req == TASKSTATS_CMD_GET)
        task_ret = parse_taskmsg(TASKSTATS_TYPE_STATS, &msg);
    else if (req == CTRL_CMD_GETFAMILY)
        task_ret = parse_taskmsg(CTRL_ATTR_FAMILY_ID, &msg);

    return task_ret;
}

static int get_nl_family_id(profile_t *process)
{
    void *family_id = make_nl_req(CTRL_CMD_GETFAMILY, process);

    if (family_id)
        return *(int *) family_id;

    return -1;
}

void pid_name(profile_t *process)
{
    char *name = NULL;

    if (!is_alive(process)) 
        goto assign_name;

    char *path;
    CONSTRUCT_PATH(path, "%s%s%s", 3, PROC, process->pidstr, COMM);
    FILE *proc = fopen(path, "r");

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

void get_process_nice(profile_t *process)
{
    if (process->uid == 0) {
        struct taskstats *st = (struct taskstats *) make_nl_req(
                                TASKSTATS_CMD_GET, process);
        if (st)
            process->nice = st->ac_nice;
        else
            process->nice_err = -1;

        return;
    }

    errno = 0;

    int nice = getpriority(PRIO_PROCESS, process->pid);

    if (errno != 0)
        process->nice_err = errno;
    else
        process->nice = nice;
}

void set_pid_nice(profile_t *process, int priority)
{
    if (setpriority(PRIO_PROCESS, process->pid, priority) < 0)
        process->nice_err = -1;
    else
        process->nice = priority;
}

static void get_ioprio_nice(profile_t *process, int ioprio)
{
    get_process_nice(process);
    int ioprio_level = (process->nice + 20) / 5;
    int prio = sched_getscheduler(process->pid);

    if (prio == SCHED_FIFO || prio == SCHED_RR) {        
        process->ioprio = malloc(IOPRIO_LEN(class[1]));
        snprintf(process->ioprio, IOPRIO_LEN(class[1]), 
                 "%s%d", class[1], ioprio_level);
    } else if (prio == SCHED_OTHER) {
        process->ioprio = malloc(IOPRIO_LEN(class[2]));
        snprintf(process->ioprio, IOPRIO_LEN(class[2]), 
                 "%s%d", class[2], ioprio_level);
    } else {
        process->ioprio = malloc(strlen(class[3]) + 1);
        snprintf(process->ioprio, IOPRIO_LEN(class[3]), "%s", class[3]);
    }
}

void get_ioprio(profile_t *process)
{
    process->ioprio= NULL;

    int ioprio = syscall(GETIOPRIO, IOPRIO_WHO_PROCESS, process->pid);

    if (ioprio == -1)
        return;

    if (IOPRIO_CLASS(ioprio) != 0) {
        process->ioprio = malloc(IOPRIO_LEN(class[IOPRIO_CLASS(ioprio)]));
        snprintf(process->ioprio, IOPRIO_LEN(class[IOPRIO_CLASS(ioprio)]), 
                 "%s%ld", class[IOPRIO_CLASS(ioprio)], IOPRIO_DATA(ioprio));
    } else
        get_ioprio_nice(process, ioprio);
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
   
    int thread_cnt = 0;
    while ((task = readdir(task_dir))) {
        if (!(ispunct(*(task->d_name)))) 
            process->threads[thread_cnt++] = atoi(task->d_name);
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
    if (fread(status, 1, STATUS_SIZE - 1, fp) < 0)
        goto close_path;

    char *delimiter = "\n";
    char *field_token = strtok(status, delimiter);

    char *value = NULL;
    while (field_token) {
        if (strstr(field_token, field)) {
            char *value_raw = strchr(field_token, '\t');
            for (; !isdigit(*value_raw); value_raw++);
            value = malloc(MAX_FIELD);
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

void getusernam(profile_t *process)
{
    struct passwd *username = getpwuid(process->uid);
    process->username = username->pw_name;
}

void voluntary_context_switches(profile_t *process)
{
    if (process->uid == 0) {
        struct taskstats *st = (struct taskstats *) make_nl_req(
                                      TASKSTATS_CMD_GET, process);
        if (st)
            process->vol_ctxt_swt = st->nvcsw;
        else
            process->invol_ctxt_swt = -1;

        return;
    }

    char *vswitch = parse_status_fields(process->pidstr, 
                               "voluntary_ctxt_switches");
    if (vswitch) { 
        process->vol_ctxt_swt = atol(vswitch);
        free(vswitch);
    } else
        process->vol_ctxt_swt = -1;
}
// mark as netlink // or ...
void involuntary_context_switches(profile_t *process)
{
    char *invol_switch = "nonvoluntary_ctxt_switches";
    char *ivswitch = parse_status_fields(process->pidstr, invol_switch);
    if (ivswitch) {
        process->invol_ctxt_swt = atol(ivswitch);
        free(ivswitch);
    }
}
// mark as netlink // or ...
void virtual_mem(profile_t *process)
{
    char *virtual_memory = "VmSize";
    char *total_memory = parse_status_fields(process->pidstr, virtual_memory);
    if (total_memory) {
        process->vmem = atol(total_memory);
        free(total_memory);
    }
}

profile_t *init_profile(int pid)
{
    profile_t *profile = calloc(sizeof *profile, 1);
    profile->pidstr = malloc(MAXPID);
    snprintf(profile->pidstr, MAXPID - 1, "%d", pid);

    if (!is_alive(profile))
        goto profile_error;
 
    profile->pid = pid;

    uid_t user = geteuid();

    if (user == 0) {
        profile->nl_conn = create_nl_conn();
        profile->nl_family_id = get_nl_family_id(profile);
    } else 
        profile->nl_conn = -1;
    profile->uid = user;

    return profile; 

profile_error:

    free(profile->pidstr);
    free(profile);

    return NULL;
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

    if (process->nl_conn != -1)
        close(process->nl_conn);

    if (process->pidstr)
        free(process->pidstr);

    if (process->name)
        free(process->name);

    if (process->ioprio)
        free(process->ioprio);

    if (process->fd)
        free_profile_fd(process);

    free(process);
}
