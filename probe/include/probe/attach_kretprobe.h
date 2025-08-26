/*
 * Implementation of kretprobe using tracefs
 * Add the maxactive option configuration for kretprobe
 * Based on the bcc implementation
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define PATH_MAX 300

#define DEBUGFS_TRACEFS "/sys/kernel/debug/tracing"
#define TRACEFS "/sys/kernel/tracing"

static const char *get_tracefs_path()
{
    return DEBUGFS_TRACEFS;
    // return TRACEFS;
}

#define MAX_EVENT_STRING_LEN 300
#define MAX_EVENTS_CNT 30
struct attached_events{
    char events_name[MAX_EVENTS_CNT][MAX_EVENT_STRING_LEN];
    int attached_cnt;
};

static struct attached_events my_events = {
    .events_name = {},
    .attached_cnt = 0,
};


/* Creates an [uk]probe using tracefs.
 * On success, the path to the probe is placed in buf (which is assumed to be of size PATH_MAX).
 */
static int create_probe_event(char *buf, const char *ev_name,
                              const char *config1, 
                              const char *event_type, pid_t pid, int maxactive)
{
    int kfd = -1, res = -1;
    char ev_alias[256];
    bool is_kprobe = strncmp("kprobe", event_type, 6) == 0;

    snprintf(buf, PATH_MAX, "%s/%s_events", get_tracefs_path(), event_type);
    kfd = open(buf, O_WRONLY | O_APPEND, 0);
    if (kfd < 0) {
        fprintf(stderr, "%s: open(%s): %s\n", __func__, buf,
                strerror(errno));
        return -1;
    }

    res = snprintf(ev_alias, sizeof(ev_alias), "%s_bcc_%d", ev_name, getpid());
    if (res < 0 || res >= sizeof(ev_alias)) {
        fprintf(stderr, "Event name (%s) is too long for buffer\n", ev_name);
        close(kfd);
        return -1;
    }

    snprintf(buf, PATH_MAX, "r%d:kprobes/%s %s", maxactive, ev_alias, config1);

    if (write(kfd, buf, strlen(buf)) < 0) {
        if (errno == ENOENT)
            fprintf(stderr, "cannot attach %s, probe entry may not exist\n", event_type);
        else
            fprintf(stderr, "cannot attach %s, %s\n", event_type, strerror(errno));
        close(kfd);
        return -1;
    }
    close(kfd);
    snprintf(buf, PATH_MAX, "%s/events/%ss/%s", get_tracefs_path(),
            event_type, ev_alias);
    return 0;
}

// config1 could be either kprobe_func or uprobe_path,
// see bpf_try_perf_event_open_with_probe().
static int bpf_attach_probe(int progfd, const char *ev_name, 
                            const char *config1, const char* event_type,
                            pid_t pid, int maxactive)
{
  int kfd, pfd = -1;
  char buf[PATH_MAX], fname[256], kprobe_events[PATH_MAX];
  bool is_kprobe = strncmp("kprobe", event_type, 6) == 0;

    if (create_probe_event(buf, ev_name, config1, event_type, pid, maxactive) < 0){
        // bpf_close_perf_event_fd(pfd);
        return -1;
    }
      

    // If we're using maxactive, we need to check that the event was created
    // under the expected name.  If tracefs doesn't support maxactive yet
    // (kernel < 4.12), the event is created under a different name; we need to
    // delete that event and start again without maxactive.
    // if (is_kprobe && maxactive > 0 && attach_type == BPF_PROBE_RETURN) {
    if (snprintf(fname, sizeof(fname), "%s/id", buf) >= sizeof(fname)) {
        fprintf(stderr, "filename (%s) is too long for buffer\n", buf);
        // bpf_close_perf_event_fd(pfd);
        return -1;
    }
    if (access(fname, F_OK) == -1) {
        snprintf(kprobe_events, PATH_MAX, "%s/kprobe_events", get_tracefs_path());
        // Deleting kprobe event with incorrect name.
        kfd = open(kprobe_events, O_WRONLY | O_APPEND, 0);
        if (kfd < 0) {
            fprintf(stderr, "open(%s): %s\n", kprobe_events, strerror(errno));
            return -1;
        }
        snprintf(fname, sizeof(fname), "-:kprobes/%s_0", ev_name);
        if (write(kfd, fname, strlen(fname)) < 0) {
            if (errno == ENOENT)
                fprintf(stderr, "cannot detach kprobe, probe entry may not exist\n");
            else
                fprintf(stderr, "cannot detach kprobe, %s\n", strerror(errno));
            close(kfd);
            return -1;
        }
        close(kfd);

        // Re-creating kprobe event without maxactive.
        if (create_probe_event(buf, ev_name, config1, event_type, pid, 0) < 0)
        {
            return -1;
        }
            
    }
    else{
        // record the attached events
        if(my_events.attached_cnt < MAX_EVENTS_CNT){
            char ev_alias[256];
            int res = snprintf(ev_alias, sizeof(ev_alias), "%s_bcc_%d", ev_name, getpid());
            if (res < 0 || res >= sizeof(ev_alias)) {
                fprintf(stderr, "Event name (%s) is too long for buffer of the attached events\n", ev_name);
            }
            snprintf(my_events.events_name[my_events.attached_cnt], MAX_EVENT_STRING_LEN, "-:kprobes/%s", ev_alias);
            printf("write events! %s\n", my_events.events_name[my_events.attached_cnt]);
            my_events.attached_cnt += 1;
            
        }
    }

    return -1;
}

// attach kretprobe program
int attach_kretprobe(int progfd, const char* event, const char* fn_name, int maxactive = 0)
{
    char ev_name[PATH_MAX];
    snprintf(ev_name, sizeof(ev_name), "r_%s", event);
    bpf_attach_probe(progfd, ev_name, event, "kprobe", -1, maxactive);
}


// detach kretprobe program
int detach_kretprobe(){
    // echo "" > /sys/kernel/debug/tracing/kprobe_events
    // echo -:kprobes/r_sock_recvmsg_bcc_669969 >> /sys/kernel/debug/tracing/kprobe_events

    printf("Enter! detach_kertprobe()\n");
    char kprobe_events[PATH_MAX];
    snprintf(kprobe_events, PATH_MAX, "%s/kprobe_events", get_tracefs_path());
    // Deleting kprobe event with incorrect name.
    int kfd = open(kprobe_events, O_WRONLY | O_APPEND, 0);
    if (kfd < 0) {
        fprintf(stderr, "open(%s): %s\n", kprobe_events, strerror(errno));
        return -1;
    }

    for(int i = 0; i < my_events.attached_cnt; i ++){
        printf("my_events: %s\n", my_events.events_name[i]);
        if (write(kfd, my_events.events_name[i], strlen(my_events.events_name[i])) < 0) {
            if (errno == ENOENT)
                fprintf(stderr, "cannot detach kprobe, probe entry may not exist\n");
            else
                fprintf(stderr, "cannot detach kprobe, %s\n", strerror(errno));
            close(kfd);
            // bpf_close_perf_event_fd(pfd);
            return -1;
        }
    }
    close(kfd);
    return 0;
}
