/*
 * Load eBPF programs
 */

#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include "attach_kretprobe.h"
#include "probe.skel.h"

#define TC_HOOKS_MAX 20
struct bpf_tc_opts tc_opts_array[TC_HOOKS_MAX] = {};
struct bpf_tc_hook tc_hook_array[TC_HOOKS_MAX] = {};
unsigned int tc_hook_num = 0;

#define CNI0_IFINDEX 1592
struct bpf_xdp_attach_opts xdp_opt = {};


#define DEBUGBPF
// BIMP RLIMIT_MEMLOCK
static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

// libbpf print function
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
        #ifdef DEBUGBPF
	        return vfprintf(stderr, format, args);
        #else
	        return 0;
        #endif
}


// detach TC programs
int detachTCPrograms(){
	for(int i = 0; i < tc_hook_num;  i ++){
		tc_opts_array[i].flags = tc_opts_array[i].prog_fd = tc_opts_array[i].prog_id = 0;
		int err = bpf_tc_detach(&tc_hook_array[i], &tc_opts_array[i]);
		if (err) {
			fprintf(stderr, "Failed to detach TC: %d\n", err);
			bpf_tc_hook_destroy(&tc_hook_array[i]);
		}
	}
}

// Load TC programs
int loadTCPrograms_Ingress(struct probe_bpf * skel){
        // attach to the ingress of the cni0 interface
	tc_hook_array[tc_hook_num].ifindex = CNI0_IFINDEX; // cni0
	tc_hook_array[tc_hook_num].attach_point = BPF_TC_INGRESS;
	tc_hook_array[tc_hook_num].sz = sizeof(bpf_tc_hook);
	tc_opts_array[tc_hook_num].handle = 1;
	tc_opts_array[tc_hook_num].priority = 1;
	tc_opts_array[tc_hook_num].sz = sizeof(bpf_tc_opts);

	bool hook_created = false;
	int err = bpf_tc_hook_create(tc_hook_array+tc_hook_num);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		detachTCPrograms();
	}
	tc_opts_array[tc_hook_num].prog_fd = bpf_program__fd(skel->progs.tc_ingress);
	err = bpf_tc_attach(&tc_hook_array[tc_hook_num], &tc_opts_array[tc_hook_num]);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		detachTCPrograms();
	}
	tc_hook_num ++;

	// attach to the egress of the cni0 interface
	tc_hook_array[tc_hook_num].ifindex = CNI0_IFINDEX; // cni0
	tc_hook_array[tc_hook_num].attach_point = BPF_TC_EGRESS;
	tc_hook_array[tc_hook_num].sz = sizeof(bpf_tc_hook);
	tc_opts_array[tc_hook_num].handle = 1;
	tc_opts_array[tc_hook_num].priority = 1;
	tc_opts_array[tc_hook_num].sz = sizeof(bpf_tc_opts);

	hook_created = false;
	err = bpf_tc_hook_create(tc_hook_array+tc_hook_num);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		detachTCPrograms();
	}
	tc_opts_array[tc_hook_num].prog_fd = bpf_program__fd(skel->progs.tc_egress);
	err = bpf_tc_attach(&tc_hook_array[tc_hook_num], &tc_opts_array[tc_hook_num]);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		detachTCPrograms();
	}
	tc_hook_num ++; 
        
        return 0;

}


// detach XDP program
int detachXDPrograms(){
	int err = bpf_xdp_detach(CNI0_IFINDEX, 0, NULL); 
	if (err) {
		fprintf(stderr, "Failed to detach XDP: %d\n", err);
	}
        return 0;
}

// Load XDP program
int loadXDPrograms(struct probe_bpf * skel){
	xdp_opt.old_prog_fd = -1; // lo
	xdp_opt.sz = sizeof(struct bpf_xdp_attach_opts);
	
	int prog_fd = bpf_program__fd(skel->progs.xdp_cni0_prog);
	int err = bpf_xdp_attach(CNI0_IFINDEX, prog_fd, 0, &xdp_opt);
	if (err) {
		fprintf(stderr, "Failed to attach XDP: %d\n", err);
		detachXDPrograms();
	}

}



// Load libbpf programs
int load_libbpf_programs(struct probe_bpf * skel){
	
	int err = 0;
	err = loadTCPrograms_Ingress(skel);
	err = loadXDPrograms(skel);

        printf("Load eBPF programs: err = %d\n", err);

    return err!=0;
}



// load skeleton and attach programs
int loadSkelFuncs(struct probe_bpf *skel){
        // load libbpf programs
        int err = 0;
                
        err = load_libbpf_programs(skel);
        err = probe_bpf__attach(skel);
        printf("ERR: %d\n", err);
        if (err) {
                fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
                probe_bpf__destroy(skel);
                return err !=0;
        }
        
	return err != 0;
}
