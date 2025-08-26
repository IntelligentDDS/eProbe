#include <stdio.h>
#include <fcntl.h>
#include <sys/resource.h> 
#include <errno.h>
#include <signal.h>
#include <bpf/bpf.h>

#include "probe.bpf.h"
#include "linux_bpf.h"
#include "probe.skel.h"
#include "config.h"
#include "bpf_user.h"
#include "cmdline.h"
#include "k8s.h"


using namespace std;



static volatile bool exiting = false;
static void sig_handler(int sig)
{
        exiting = true;
}


// initialize some settings
void init(){
	// set the bpf settings
	libbpf_set_print(libbpf_print_fn);
	bump_memlock_rlimit();

	/* Clean handling of Ctrl-C */
        signal(SIGINT, sig_handler);
        signal(SIGTERM, sig_handler);
}

// read the command line, parse the config.
int parseCmdline(int argc, char *argv[]){
        // create a parser
        cmdline::parser cmdline_parser;
        // add specified type of variable.
        // 1st argument is long name
        // 2nd argument is short name (no short name if '\0' specified)
        // 3rd argument is description
        // 4th argument is mandatory (optional. default is false)
        // 5th argument is default value  (optional. it used when mandatory is false)
        cmdline_parser.add<string>("config", 'c', "config path", true, "");

        // Run parser.
        // It returns only if command line arguments are valid.
        // If arguments are invalid, a parser output error msgs then exit program.
        // If help flag ('--help' or '-?') is specified, a parser output usage message then exit program.
        cmdline_parser.parse_check(argc, argv);

        // use flag values
        cout << cmdline_parser.get<string>("config") <<  endl;

        // if has valid config，read and parse it
        string config_path = cmdline_parser.get<string>("config");
        return readConfigYaml(config_path);
}

struct ringbuff_event{
    __u32 ip4;           // not ready ip
    __u16 reason_type;   // reason type: 1 - response time, 2 - response ratio, 3 - connection, 4 - error rate
} __attribute__((packed));


// ring buffer event handler
int handle_event(void *ctx, void *data, size_t data_sz)
{
        const struct ringbuff_event *e = (struct ringbuff_event *) data;

	struct tm *tm;
        char ts[32];
        time_t t;

        time(&t);
        tm = localtime(&t);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);
        // print the event: ip4, reason_type
        printf("%-8s %-12x %-4d\n", ts, e->ip4, e->reason_type);
        return 0;
}

// main function
int main(int argc, char *argv[]){

        // initialize
        init();
        printf("Begin: open eBPF monitor skeleton!\n");

        // load skeleton
        struct probe_bpf *skel = probe_bpf__open_and_load();
	if (!skel){
                printf("ERROR: Failed to open eBPF monitor skeleton!\n");
                probe_bpf__destroy(skel);
                return -1;
        }else{
                printf("SUCCESS: Open eBPF monitor skeleton!\n");
        }

        int ret = loadSkelFuncs(skel);
        if(ret != 0){
                printf("Error: Failed to load kernel function!\n");
                return ret;
        }

        // update the target IP to eBPF map
        update_target_ip(skel, readKubeletProbeIP());
        
        /* Set up ring buffer polling */
        int err = 0;
        struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.not_ready_ringbuf), handle_event, NULL, NULL);
        if (!rb) {
                err = -1;
                fprintf(stderr, "Failed to create ring buffer\n");
                ring_buffer__free(rb);
	        probe_bpf__destroy(skel);
        	return err !=0;
	}

        printf("Successfully started! Please press Ctrl-C to stop.\n");
        while (!exiting) {
                err = ring_buffer__poll(rb, 100 /* timeout, ms */);
                /* Ctrl-C will cause -EINTR */
                if (err == -EINTR) {
                        err = 0; break;
                }
                if (err < 0) {
                        printf("Error polling ring buffer: %d\n", err); break;
                }
        }

        detachXDPrograms();
        detachTCPrograms();
	probe_bpf__destroy(skel);

	return err !=0;
}
