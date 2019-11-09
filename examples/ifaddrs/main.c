#include <stdio.h>
#include <snf.h>

int main(int argc, char **argv) {
	struct snf_ifaddrs *p, *ifa;
	int rc;

	if ((rc = snf_init(SNF_VERSION_API)) != 0) {
		printf("unable to snf_init()\n");
		return 2;
	}

	if ((rc = snf_getifaddrs(&p)) != 0) {
		printf("unable to snf_getifaddrs()\n");
		return 1;
	}

	for (ifa = p; ifa != NULL; ifa = ifa->snf_ifa_next) {
		printf("next port: %d\n", ifa->snf_ifa_portnum);
	}

	snf_freeifaddrs(p);
	return 0;
}
