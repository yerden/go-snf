#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>

#include <snf.h>

#define RINGS_MAX 256

struct thread_context {
	int rc;
	pthread_t tid;

	uint64_t packets;
	int timeout_ms;
	snf_ring_t ringh;
};

static void shutdown_snf(snf_handle_t h, struct thread_context *ctx, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		snf_ring_close(ctx[n].ringh);
	}

	snf_close(h);
}

static void snf_error_exit(const char *msg, int errnum)
{
	char s[256];
	strerror_r(errnum, s, sizeof(s));
	printf("%s: %s\n", msg, s);
	exit(errnum);
}

static int is_port_valid(int n)
{
	struct snf_ifaddrs *head, *ifa;
	int rc;

	if ((rc = snf_getifaddrs(&head)) != 0) {
		snf_error_exit("snf_getifaddrs", rc);
	}

	int found = 0;
	for (ifa = head; ifa != NULL; ifa = ifa->snf_ifa_next) {
		if ((int)ifa->snf_ifa_portnum == n) {
			found = 1;
			break;
		}
	}

	snf_freeifaddrs(head);
	return found;
}

static volatile uint8_t exit_mark = 0;

static void signal_handler(int sig, siginfo_t * info, void *ucontext)
{
	exit_mark = 1;
}

static void *ring_handler(void *arg)
{
	struct thread_context *ctx = arg;
	struct snf_recv_req recv_req;
	int rc;

	while (0 == exit_mark) {
		rc = snf_ring_recv(ctx->ringh, ctx->timeout_ms, &recv_req);
		if (rc == EAGAIN || rc == EINTR) {
			continue;
		} else if (rc != 0) {
			ctx->rc = rc;
			break;
		}

		/* payload job */
		ctx->packets++;
	}

	pthread_exit(NULL);
}

static int threads_create(struct thread_context *contexts, int n, int timeout_ms)
{
	int i, rc;
	for (i = 0; i < n; i++) {
		struct thread_context *ctx = &contexts[i];
		ctx->timeout_ms = timeout_ms;

		printf("Start reading on ring %d...\n", i);
		if ((rc = pthread_create(&ctx->tid, NULL, ring_handler, ctx)) != 0) {
			return 0;
		}
	}

	return 1;
}

static int setup_sigaction()
{
	int i, rc;
	struct sigaction snf_action;
	int signals[] = { SIGINT, SIGTERM, SIGSEGV };

	sigemptyset(&snf_action.sa_mask);
	for (i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
		sigaddset(&snf_action.sa_mask, signals[i]);
	}

	snf_action.sa_flags |= SA_SIGINFO;
	snf_action.sa_sigaction = signal_handler;

	for (i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
		if ((rc = sigaction(signals[i], &snf_action, NULL)) != 0) {
			return rc;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int rc = 0;

	/* installing signal handler. */
	if ((rc = setup_sigaction()) != 0) {
		snf_error_exit("error setting sigaction", rc);
	}

	/* initialize SNF */
	if ((rc = snf_init(SNF_VERSION_API)) != 0) {
		snf_error_exit("snf_init", rc);
	}

	int c, n = -1;
	int timeout_ms = 0;

	while ((c = getopt(argc, argv, "n:t:")) != -1) {
		switch (c) {
		case 'n':
			n = atoi(optarg);
			break;
		case 't':
			timeout_ms = atoi(optarg);
			break;
		}
	}

	if (!is_port_valid(n)) {
		snf_error_exit("Specify valid port number via '-n'", n);
	}

	snf_handle_t handle;

	printf("Initializing port %d.\n", n);
	if ((rc = snf_open_defaults((uint32_t) n, &handle)) != 0) {
		snf_error_exit("snf_open_defaults", rc);
	}

	struct thread_context contexts[RINGS_MAX];
	memset(contexts, 0, sizeof(contexts));

	int n_rings;

	printf("Initializing rings.\n");
	for (n_rings = 0; n_rings < RINGS_MAX; n_rings++) {
		struct thread_context *ctx = &contexts[n_rings];
		if ((rc = snf_ring_open(handle, &ctx->ringh)) == EBUSY) {
			break;
		}

		if (rc != 0) {
			snf_error_exit("SNF new ring error", rc);
		}
	}

	if (n_rings == RINGS_MAX) {
		snf_error_exit("Too many rings", n_rings);
	}

	if (n_rings == 0) {
		snf_error_exit("No rings available", rc);
	}

	printf("Initialized %d rings.\n", n_rings);

	if ((rc = snf_start(handle)) != 0) {
		shutdown_snf(handle, contexts, n_rings);
		snf_error_exit("snf_start", rc);
	}

	if (!threads_create(contexts, n_rings, timeout_ms)) {
		shutdown_snf(handle, contexts, n_rings);
		snf_error_exit("pthread create", rc);
	}

	/* waiting to be closed */
	for (c = 0; c < n_rings; c++) {
		struct thread_context *ctx = &contexts[c];
		pthread_join(ctx->tid, NULL);
		printf("exited ring %d, rc = %d, read %ld packets.\n", c, ctx->rc, ctx->packets);
	}

	shutdown_snf(handle, contexts, n_rings);
	return 0;
}
