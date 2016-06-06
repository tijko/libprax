#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#ifdef __x86_64__
#define SETIOPRIO 251
#define GETIOPRIO 252
#define TGKILL 234
#elif __i386__
#define SETIOPRIO 289
#define GETIOPRIO 290
#define TGKILL 270
#endif

#define MAXPID 16
#define IOPRIO_SIZE 6 

#define LINE_SZ 256

// Buffer size for readlink calls
#define LINKBUFSIZ 1024

#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/resource.h>

static char *class[4] = {"", "rt/", "be/", "idle"};

// Typedef to contain stats of file-descriptors.
typedef struct fdstats fdstats_t;

struct fdstats {
    char *file;
    struct stat *file_stats;
    fdstats_t *next_fd;
};

// Typedef of the process being profiled.
typedef struct profile profile_t;

struct profile {
    int pid;
    int uid;
    int tgid;
    int ctty;
    int nice;
    int cpu_affinity;
    int thread_count;
    int threads[256];
    long vol_ctxt_swt;
    long invol_ctxt_swt;
    long vmem;
    char *pidstr;
    char *name;
    char *username;
    char *ioprio;
    pid_t sid;
    
    rlim_t addr_space_cur;
    rlim_t addr_space_max;
    rlim_t core_cur;
    rlim_t core_max;
    rlim_t cpu_cur;
    rlim_t cpu_max;
    rlim_t data_cur;
    rlim_t data_max;
    rlim_t fsize_cur;
    rlim_t fsize_max;
    rlim_t locks_cur;
    rlim_t locks_max;
    rlim_t memlock_cur;
    rlim_t memlock_max;
    rlim_t msgqueue_cur;
    rlim_t msgqueue_max;
    rlim_t nice_cur;
    rlim_t nice_max;
    rlim_t nofile_cur;
    rlim_t nofile_max;
    rlim_t nproc_cur;
    rlim_t nproc_max;
    rlim_t rss_cur;
    rlim_t rss_max;
    rlim_t rtprio_cur;
    rlim_t rtprio_max;
    rlim_t rttime_cur;
    rlim_t rttime_max;
    rlim_t sigpending_cur;
    rlim_t sigpending_max;
    rlim_t stack_cur;
    rlim_t stack_max;

    fdstats_t *fd;
};

// Check if process exists.
bool is_alive(profile_t *process);

// Count digit places in type int of the process being profiled.
int pid_digit_places(int pid);

// Function returns the niceness of the pid being profiled.
void get_pid_nice(profile_t *process);

// Sets the niceness of pid.
void set_pid_nice(profile_t *process, int priority);

#define PROC "/proc/"
#define PROCLEN 6

// Constructs the path from the pid and specific dir being looked up.
char *construct_path(int pathparts, ...);

#define STATUS "/status"
#define COMM "/comm"
#define TASK "/task"
#define FD "/fd/"

// Function to return the name of a pid.
void pid_name(profile_t *process);

// A function that traverses the "fd" directory of the pid from process
// and loads a fdstat_t struct with stats for each file-descriptor found.
int process_fd_stats(profile_t *process);

//XXX These definitions are from linux/ioprio.h
#define IOPRIO_WHO_PROCESS 1
#define IOPRIO_SHIFT 13

enum {
    IOPRIO_CLASS_NONE,
    IOPRIO_CLASS_RT,
    IOPRIO_CLASS_BE,
    IOPRIO_CLASS_IDLE,
};

#define IOPRIO_PRIO_MASK ((1UL << IOPRIO_SHIFT) - 1)

#define IOPRIO_CLASS(mask) ((mask) >> IOPRIO_SHIFT)
#define IOPRIO_DATA(mask) ((mask) & IOPRIO_PRIO_MASK)
#define IOPRIO_VALUE(class, data) (((class) << IOPRIO_SHIFT) | data)

#define IOPRIO_LEN(class) strlen(class) + IOPRIO_SIZE

// Returns the I/O scheduling class and priority of profiled pid.
void get_ioprio(profile_t *process);

void get_ioprio_nice(profile_t *process, int ioprio);

// Sets the I/O scheduling class and priority of profiled pid.
void set_ioprio(profile_t *process, int class, int value);

// sets/gets process resource limits.
void rlim_stat(profile_t *process, int resource, unsigned long *limit);

// gets/sets the current processor affinity in profile_t struct;
void cpu_affinity(profile_t *process);

void setcpu_affinity(profile_t *process, int affinity);

// sets the session id field in profile_t struct
void process_sid(profile_t *process);

// populates the 'threads' array in process struct if any threads are running.
void running_threads(profile_t *process);

// kills a thread under the current processes group with the provided id.
void tkill(profile_t *process, int tid);

// sets the 'tgid' field of the processes thread group id number.
void gettgid(profile_t *process);

// sets the 'uid' field of the processes uid number.
void getpuid(profile_t *process);

// sets the 'username' field of process provided.
void getusernam(profile_t *process);

// will find the number voluntary context switches for a process.
void voluntary_context_switches(profile_t *process);

// will find the number involuntary context switches for a process.
void involuntary_context_switches(profile_t *process);

// specifies the amount of virtual memory in use by a process.
void virtual_mem(profile_t *process);
    
// passing in a `char *` of a processes pid and a field e.g. ('uid', 'tgid', 'username')
// will parse the proc fs the processes status file and return said field.
char *parse_status_fields(char *pid, char *field);

// Parses the stat file of the procfs.  By passing in a field number the 
// parser function will return the field that is listed after the number of 
// spaces equal to that number.
char *parse_stat(char *pid, int field);


#define MAXVAL 64

// Initializer for the profile_t type.
profile_t init_profile(void);

// Free memory used by a profile_t type file descriptors field.
void free_profile_fd(profile_t *process);

// Free memory used by a profile_t type.
void free_profile(profile_t *process);
