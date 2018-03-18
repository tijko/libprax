#include "prax.h"

#include <pwd.h>
#include <stdio.h>
#include <ctype.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/syscall.h>


bool is_alive(profile_t *process)
{
    if (!opendir(process->procfs_base))
        return false;

    return true;
}

static inline void procfs_filename(char *base, char *field, size_t len)
{
    int field_len = strlen(field);

    for (int i=0; i < field_len; i++)
        base[len + i] = field[i];

    base[len + field_len] = '\0';
}

static char *parse_status_fields(profile_t *p, char *field, int (*accept_char)(int c))
{
    p->procfs_base[p->procfs_len] = '\0';
    procfs_filename(p->procfs_base, STATUS, p->procfs_len);

    FILE *fp = fopen(p->procfs_base, "r");
    if (!fp)
        return NULL;

    char status[STATUS_SIZE];
    if (fread(status, 1, STATUS_SIZE - 1, fp) < 0)
        goto close_path;

    char *delimiter = "\n";
    char *field_token = strtok(status, delimiter);

    char *value = NULL;
    while (field_token) {
        if (strstr(field_token, field)) {
            char *value_raw = strchr(field_token, '\t');
            for (; isblank(*value_raw); value_raw++);
            value = malloc(MAX_FIELD);
            int idx = 0;
            for (; idx < MAX_FIELD - 1 && accept_char(value_raw[idx]); idx++)
                value[idx] = value_raw[idx];
            value[idx] = '\0';
            goto close_path;
        }

        field_token = strtok(NULL, delimiter);
    }

close_path:
    fclose(fp);

    return value;
}

int yama_enabled(void)
{
    FILE *fh = fopen(YAMA, "r");

    if (!fh)
        return 0;

    char yama_byte;

    if (fread(&yama_byte, 1, 1, fh) < 0)
        return 0;

    return yama_byte == '1';
}

int is_traced(profile_t *process)
{
    char *tracer_pidstr = parse_status_fields(process, "TracerPid", isdigit);
    if (!tracer_pidstr)
        return 0;

    errno = 0;
    strtol(tracer_pidstr, NULL, 0);
    return errno ? 0 : 1;
}

void get_trace_pid(profile_t *process)
{
    char *tracer_pidstr = parse_status_fields(process, "TracerPid", isdigit);
    errno = 0;
    process->trace_pid = strtol(tracer_pidstr, NULL, 0);
    if (errno)
        process->trace_pid = 0;
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
    struct taskmsg *msg = calloc(1, sizeof *msg);
    void *task_ret = NULL;

    int data_len;

    switch (req) {

        case (CTRL_CMD_GETFAMILY):
            data_len = strlen(TASKSTATS_GENL_NAME) + 1;
            build_req(msg, GENL_ID_CTRL, req, CTRL_ATTR_FAMILY_NAME,
                       data_len, TASKSTATS_GENL_NAME);
            break;
        case (TASKSTATS_CMD_GET):
            build_req(msg, process->nl_family_id, req,
                TASKSTATS_CMD_ATTR_PID, sizeof(int), &(process->pid));
            break;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof addr);
    addr.nl_family = AF_NETLINK;
    
    int msglength = msg->nl.nlmsg_len;
    char *msg_buffer = (char *) msg;

    while (msglength > 0) {
        int bytes_sent = sendto(process->nl_conn, msg_buffer, msglength, 0,
                            (struct sockaddr *) &addr, sizeof addr);
        if (bytes_sent < 0)
            goto release;
        msglength -= bytes_sent;
        msg_buffer += bytes_sent;
    }
    
    memset(msg, 0, sizeof *msg);
    
    if (recv_nl_req(process->nl_conn, msg) < 0)
        goto release;

    // rm copy dup
    if (req == TASKSTATS_CMD_GET) {
        void *parse_results = parse_taskmsg(TASKSTATS_TYPE_STATS, msg);
        if (parse_results) {
            task_ret = malloc(sizeof(struct taskstats));
            memcpy(task_ret, parse_results, sizeof(struct taskstats));
        }
    } else if (req == CTRL_CMD_GETFAMILY) {
        void *parse_results = parse_taskmsg(CTRL_ATTR_FAMILY_ID, msg);
        if (parse_results) {
            task_ret = malloc(sizeof(int));
            memcpy(task_ret, parse_results, sizeof(int));
        }
    }

release:
    free(msg);

    return task_ret;
}

#define TASK_REQ(profile, field, p_off, size)                             \
    get_task_field(profile, offsetof(struct taskstats, field), p_off, size)

static void get_task_field(profile_t *process, int st_off, 
                                   int p_off, size_t size)
{
    struct taskstats *st = (struct taskstats *) make_nl_req(TASKSTATS_CMD_GET, 
                                                                     process);
    
    if (st == NULL)
        return;

    *(((char *) process) + p_off) = *(((char *) st) + st_off);
}

static int get_nl_family_id(profile_t *process)
{
    void *family_id = make_nl_req(CTRL_CMD_GETFAMILY, process);

    if (family_id) {
        int id = *(int *) family_id;
        free(family_id);
        return id;
    }

    return -1;
}

int get_signals(profile_t *process)
{
    if (!process)
        return -1;

    procfs_filename(process->procfs_base, STATUS, process->procfs_len);

    char buf[STATUS_SIZE] = { '\0' };

    FILE *fp = fopen(process->procfs_base, "r");
    if (!fp)
        return -1;

    if (fread(buf, STATUS_SIZE - 1, 1, fp) < 0)
        goto error;

    char *d1 = "Q";
    char *d2 = "\t";

    char *signals = strtok(buf, d1);
    if (!signals) 
        goto error;

    signals = strtok(NULL, d2);
    char signal_bytes[32] = { '\0' };
    long *psig = (long *) &(process->psig);
    for (int i=0; i < 6; i++, psig++) {
        signals = strtok(NULL, d2);
        for (int j=1; isalnum(signals[j]); j++)
            signal_bytes[j - 1] = signals[j];
       *psig = strtol(signal_bytes, NULL, 16); 
    }

    return 0;

error:
    fclose(fp);
    return -1;
}

int pid_name(profile_t *process)
{
    procfs_filename(process->procfs_base, COMM, process->procfs_len);

    FILE *proc = fopen(process->procfs_base, "r");

    if (proc == NULL) 
        return -1;

    if (fscanf(proc, "%32c", process->name) < 1)
        return -1;

    fclose(proc);
    process->name[strlen(process->name) - 1] = '\0';

    return 0;
}

static void set_realpath(char *path, fdstats_t *fdstats)
{
    char realpath[PATH_MAX + 1] = { '\0' };
    size_t len;

    fdstats->file = NULL;

    if ((len = readlink(path, realpath, PATH_MAX)) < 0)
        return;

    realpath[len] = '\0';

    fdstats->file = strdup(realpath);
}

int process_fd_stats(profile_t *process)
{
    struct dirent *files;

    size_t procfs_len = process->procfs_len;
    char *base = (char *) &(process->procfs_base);
    procfs_filename(base, FD, procfs_len);
    procfs_len += strlen(FD);

    DIR *fd_dir = opendir(base);

    if (!fd_dir) 
        return -1;

    if (process->fd != NULL)
        free_profile_fd(process);

    if (!(process->fd = calloc(1, sizeof(fdstats_t))))
        return -1;

    process->fd->next_fd = NULL;
    fdstats_t *curr = process->fd;
     
    while ((files = readdir(fd_dir))) {
        if (files->d_type == DT_LNK) {
 
            procfs_filename(base, files->d_name, procfs_len);

            if (stat(base, &(curr->file_stats)) < 0)
                continue;

            set_realpath(base, curr);

            if (!curr->file) 
                continue;

            if (!(curr->next_fd = calloc(1, sizeof(fdstats_t))))
                break;

            curr->next_fd->next_fd = NULL;
            curr = curr->next_fd;
        }
    }

    if (fd_dir)
        closedir(fd_dir);

    return 0;
}

int get_process_nice(profile_t *process)
{
    if (process->uid == 0) {
        TASK_REQ(process, ac_nice, offsetof(profile_t, nice), sizeof(int));
        return 0;
    }

    errno = 0;

    int nice = getpriority(PRIO_PROCESS, process->pid);

    if (errno != 0) 
        return -1;

    process->nice = nice;
    return 0;
}

void set_pid_nice(profile_t *process, int priority)
{
    if (setpriority(PRIO_PROCESS, process->pid, priority) < 0)
        process->nice_err = -1;
    else
        process->nice = priority;
}

static int get_ioprio_nice(profile_t *process, int ioprio)
{
    if (get_process_nice(process) < 0)
        return -1;

    int ioprio_level = (process->nice + 20) / 5;
    int prio = sched_getscheduler(process->pid);

    if (prio < 0)
        return -1;

    const char *class_str = NULL;
    char level_str[8] = { '\0' };

    if (!(prio >> 2)) {
            class_str = nice_class[prio];
            snprintf(level_str, 7, "%d", ioprio_level);
    } else 
            class_str = nice_class[3];

    snprintf(process->ioprio, IOPRIO_LEN(class_str), "%s%s", 
                                      class_str, level_str);

    return 0;
}

int get_ioprio(profile_t *process)
{
    int ioprio = syscall(GETIOPRIO, IOPRIO_WHO_PROCESS, process->pid);

    if (ioprio < 0)
        return -1;

    if (IOPRIO_CLASS(ioprio) < 1)
        return get_ioprio_nice(process, ioprio);

    snprintf(process->ioprio, IOPRIO_LEN(prio_class[IOPRIO_CLASS(ioprio)]),
             "%s%ld", prio_class[IOPRIO_CLASS(ioprio)], IOPRIO_DATA(ioprio));
    return 0;
}

int set_ioprio(profile_t *process, int class, int value)
{
    int ioprio = IOPRIO_VALUE(class, value);
    int setioprio = syscall(SETIOPRIO, IOPRIO_WHO_PROCESS, 
                                     process->pid, ioprio);
    if (setioprio != -1)
        return get_ioprio(process);

    return 0;
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

int set_soft_rlimit(profile_t *process, int resource, unsigned long limit)
{
    struct rlimit limits = { .rlim_cur=limit };
    
    if (prlimit(process->pid, resource, &limits, NULL) < 0)
        return -1;

    return 0;
}

int set_hard_rlimit(profile_t *process, int resource, unsigned long limit)
{
    struct rlimit limits = { .rlim_max=limit };
    
    if (prlimit(process->pid, resource, &limits, NULL) < 0)
        return -1;

    return 0;
}

int get_rlimits(profile_t *process, int resource_mask)
{
    struct rlimit limits;
    pid_t pid = process->pid;
    struct proc_rlim *prlim = &(process->prlim);

    for (int i=0; i < NLIMITS; i++) {
        if (resource_mask & prlimits[i]) {
            
            int resource = prlimit_values[i];

            if (prlimit(pid, resource, NULL, &limits) < 0)
                return -1;

            switch (resource) {
                case(RLIMIT_AS): 
                    prlim->addr_space_cur = limits.rlim_cur;
                    prlim->addr_space_max = limits.rlim_max;
                    break;
                case(RLIMIT_CORE):
                    prlim->core_cur = limits.rlim_cur;
                    prlim->core_max = limits.rlim_max;
                    break;
                case(RLIMIT_CPU):
                    prlim->cpu_cur = limits.rlim_cur;
                    prlim->cpu_max = limits.rlim_max;
                    break;
                case(RLIMIT_DATA):
                    prlim->data_cur = limits.rlim_cur;
                    prlim->data_max = limits.rlim_max;
                    break;
                case(RLIMIT_FSIZE):
                    prlim->fsize_cur = limits.rlim_cur;
                    prlim->fsize_max = limits.rlim_max;
                    break;
                case(RLIMIT_LOCKS):
                    prlim->locks_cur = limits.rlim_cur;
                    prlim->locks_max = limits.rlim_max;
                    break;
                case(RLIMIT_MEMLOCK):
                    prlim->memlock_cur = limits.rlim_cur;
                    prlim->memlock_max = limits.rlim_max;
                    break;
                case(RLIMIT_MSGQUEUE):
                    prlim->msgqueue_cur = limits.rlim_cur;
                    prlim->msgqueue_max = limits.rlim_max;
                    break;
                case(RLIMIT_NICE):
                    prlim->nice_cur = limits.rlim_cur;
                    prlim->nice_max = limits.rlim_max;
                    break;
                case(RLIMIT_NOFILE):
                    prlim->nofile_cur = limits.rlim_cur;
                    prlim->nofile_max = limits.rlim_max;
                    break;
                case(RLIMIT_NPROC):
                    prlim->nproc_cur = limits.rlim_cur;
                    prlim->nproc_max = limits.rlim_max;
                    break;
                case(RLIMIT_RSS):
                    prlim->rss_cur = limits.rlim_cur;
                    prlim->rss_max = limits.rlim_max;
                    break;
                case(RLIMIT_RTPRIO):
                    prlim->rtprio_cur = limits.rlim_cur;
                    prlim->rtprio_max = limits.rlim_max;
                    break;
                case(RLIMIT_SIGPENDING):
                    prlim->sigpending_cur = limits.rlim_cur;
                    prlim->sigpending_max = limits.rlim_max;
                    break;
                case(RLIMIT_STACK):
                    prlim->stack_cur = limits.rlim_cur;
                    prlim->stack_max = limits.rlim_max;
                    break;
            }
        }
    }

    return 0;
}

int running_threads(profile_t *process)
{
    struct dirent *task;
    
    procfs_filename(process->procfs_base, TASK, process->procfs_len);

    DIR *task_dir = opendir(process->procfs_base);
    if (task_dir == NULL)
        return -1;

    int thread_cnt = 0;
    while ((task = readdir(task_dir))) {
        if (isdigit(task->d_name[0])) 
            process->threads[thread_cnt++] = atoi(task->d_name);
    }

    closedir(task_dir);
    process->thread_count = thread_cnt;
    return 0;
}

void tkill(profile_t *process, int tid)
{
    if (syscall(TGKILL, process->tgid, tid, SIGTERM) < 0)
        printf("Thread kill failed :: id - %d\n", tid);
}

static char *parse_stat(pid_t pid, int field)
{
    char *fieldstr = NULL;
    
    char path[PATH_MAX + 1];
    snprintf(path, PATH_MAX, "%s%d/stat", PROC, pid);

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

    // how expensive is strtok vs. say 1 scanf
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
        TASK_REQ(process, nvcsw, offsetof(profile_t, vol_ctxt_swt), 
                                                 sizeof(uint64_t));
        return;
    }

    char *vswitch = parse_status_fields(process, "voluntary_ctxt_switches", 
                                        isdigit);
    if (vswitch) { 
        process->vol_ctxt_swt = atol(vswitch);
        free(vswitch);
    } else
        process->vol_ctxt_swt = -1;
}

void involuntary_context_switches(profile_t *process)
{
    if (process->uid == 0) {
        TASK_REQ(process, nivcsw, offsetof(profile_t, invol_ctxt_swt),
                                                    sizeof(uint64_t));
        return;
    }

    char *invol_switch = "nonvoluntary_ctxt_switches";
    char *ivswitch = parse_status_fields(process, invol_switch, isdigit);
    if (ivswitch) {
        process->invol_ctxt_swt = atol(ivswitch);
        free(ivswitch);
    }
}

void get_start_time(profile_t *process)
{
    if (process->uid == 0) {
        TASK_REQ(process, ac_btime, offsetof(profile_t, start_time),
                                                  sizeof(uint32_t));
        return;
    }

    // Magic number?
    char *start = parse_stat(process->pid, 22);
    process->start_time = strtol(start, NULL, 0);
}

void virtual_mem(profile_t *process)
{
    if (process->uid == 0) {
        TASK_REQ(process, virtmem, offsetof(profile_t, vmem), sizeof(uint64_t));
        return;
    }

    // local static?
    char *virtual_memory = "VmSize";
    char *total_memory = parse_status_fields(process, virtual_memory, isdigit);
    if (total_memory) {
        process->vmem = atol(total_memory);
        free(total_memory);
    }
}

profile_t *init_profile(int pid)
{
    profile_t *profile = calloc(sizeof *profile, 1);
    if (!profile)
        return NULL;

    profile->pid = pid;
    if ((profile->procfs_len = snprintf(profile->procfs_base, PROCFS_MAX,
                                                 "/proc/%d/", pid)) < 0) {
        goto profile_error;
    } 
        
    if (!is_alive(profile))
        goto profile_error;
 
    if ((profile->uid = geteuid()) < 0)
        goto profile_error;

    profile->nl_conn = -1;

    if (profile->uid == 0) {
        profile->nl_conn = create_nl_conn();
        profile->nl_family_id = get_nl_family_id(profile);
    } 

    profile->fd = NULL;

    return profile; 

profile_error:

    free(profile);

    return NULL;
}

void free_profile_fd(profile_t *process)
{
    fdstats_t *curr = NULL, *next = NULL;
    
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

    if (process->nl_conn > -1)
        close(process->nl_conn);

    if (process->fd)
        free_profile_fd(process);

    free(process);
}
