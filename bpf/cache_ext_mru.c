#include <argp.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

static volatile int running = 1;

#include "cache_ext_mru.skel.h"

void handle_sig(int sig) {
    running = 0;
}

char *USAGE =
	"Usage: ./cache_ext_mru.out  --cgroup_path <path>\n";

struct cmdline_args {
	char *cgroup_path;
};

static struct argp_option options[] = { 
					{ "cgroup_path", 'c', "PATH", 0,
					  "Path to cgroup (e.g., /sys/fs/cgroup/cache_ext_test)" },
					{ 0 } };

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cmdline_args *args = state->input;
	switch (key) {
	case 'c':
		args->cgroup_path = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

int main(int argc, char **argv)
{
	signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

	int ret = 1;
	struct cache_ext_mru_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	int cgroup_fd = -1;
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	// Parse command line arguments
	struct cmdline_args args = { 0 };
	struct argp argp = { options, parse_opt, 0, 0 };
	argp_parse(&argp, argc, argv, 0, 0, &args);

	// Validate arguments
	if (args.cgroup_path == NULL) {
		fprintf(stderr, "Missing required argument: cgroup_path\n");
		return 1;
	}


	// Open cgroup directory early
	cgroup_fd = open(args.cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		perror("Failed to open cgroup path");
		return 1;
	}

	// Open skel
	skel = cache_ext_mru_bpf__open();
	if (skel == NULL) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	// Load programs
	ret = cache_ext_mru_bpf__load(skel);
	if (ret) {
		perror("Failed to load BPF skeleton");
		goto cleanup;
	}

	// Attach cache_ext_ops to the specific cgroup
	link = bpf_map__attach_cache_ext_ops(skel->maps.mru_ops, cgroup_fd);
	if (link == NULL) {
		perror("Failed to attach cache_ext_ops to cgroup");
		goto cleanup;
	}

	// Wait for keyboard input
    while (running) {
        sleep(1);
    }
	ret = 0;

cleanup:
	close(cgroup_fd);
	bpf_link__destroy(link);
	cache_ext_mru_bpf__destroy(skel);
	return ret;
}
