#include <err.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sysexits.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "options.h"
#include "ping.h"
#include "ping6.h"

enum target_type {
	TARGET_ADDRESS_IPV4,
	TARGET_ADDRESS_IPV6,
	TARGET_HOSTNAME_IPV4,
	TARGET_HOSTNAME_IPV6
};

#define MAX_TARGET_TYPES  2

static void get_target_types(const char *const target, enum target_type *types, int *const count);
static void resolv_hostname(const char *const hostname, enum target_type *types, int *const count);
static void usage(void) __dead2;

int
main(int argc, char *argv[])
{
	char *ping_target;
	int options;
	enum target_type types[MAX_TARGET_TYPES];
	int type_count;
	
	options = 0;
	ping_target = NULL;
	
	options_parse(&argc, argv, &options, &ping_target);

	if (((options & F_PROTOCOL_IPV4) && (options & F_PROTOCOL_IPV6)) || (ping_target == NULL))
		usage();
	
	get_target_types(ping_target, types, &type_count);
	
	/* Check for errors */
	if (type_count == 0)
		errx(EX_USAGE, "invalid ping target: `%s'", ping_target);
	else if (type_count == 1) {
		if ((options & F_PROTOCOL_IPV4) && (types[0] == TARGET_ADDRESS_IPV6))
			errx(EX_USAGE, "IPv4 requested but IPv6 target address provided");
		else if ((options & F_PROTOCOL_IPV6) && (types[0] == TARGET_ADDRESS_IPV4))
			errx(EX_USAGE, "IPv6 requested but IPv4 target address provided");
		else if ((options & F_PROTOCOL_IPV4) && (types[0] == TARGET_HOSTNAME_IPV6))
			errx(EX_USAGE, "IPv4 requested but the hostname has been resolved to IPv6");
		else if ((options & F_PROTOCOL_IPV6) && (types[0] == TARGET_HOSTNAME_IPV4))
			errx(EX_USAGE, "IPv6 requested but the hostname has been resolved to IPv4");
	}
	
	/* Call ping */
	if (type_count == 1) {
	       	if ((types[0] == TARGET_ADDRESS_IPV4) || (types[0] == TARGET_HOSTNAME_IPV4))
			return ping(argc, argv);
		else if ((types[0] == TARGET_ADDRESS_IPV6) || (types[0] == TARGET_HOSTNAME_IPV6))
			return ping6(argc, argv);
	} else if (options & F_PROTOCOL_IPV4)
		return ping(argc, argv);
	else if (options & F_PROTOCOL_IPV6)
		return ping6(argc, argv);
	else if (types[0] == TARGET_HOSTNAME_IPV4)
		return ping(argc, argv);
	else
		return ping6(argc, argv);
}

static void
get_target_types(const char *const target, enum target_type *types, int *const count)
{
	struct in_addr a;
	struct in6_addr a6;

	*count = 0;
	
	if (inet_pton(AF_INET, target, &a) == 1)
		types[(*count)++] = TARGET_ADDRESS_IPV4;
	else if (inet_pton(AF_INET6, target, &a6) == 1)
		types[(*count)++] = TARGET_ADDRESS_IPV6;
	else
		resolv_hostname(target, types, count);
}

static void
resolv_hostname(const char *const hostname, enum target_type *types, int *const count)
{
	struct addrinfo hints, *res, *r;

	*count = 0;
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_RAW;
	
	if (getaddrinfo(hostname, NULL, &hints, &res) == 0) {
		for (r = res; r; r = r->ai_next) {
			if (r->ai_family == AF_INET)
				types[(*count)++] = TARGET_HOSTNAME_IPV4;
			else if (r->ai_family == AF_INET6)
				types[(*count)++] = TARGET_HOSTNAME_IPV6;
		}
		
		freeaddrinfo(res);
	}
}

static void
usage(void)
{
	/* TODO */
	exit(EX_USAGE);
}
