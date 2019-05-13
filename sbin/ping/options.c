#include <unistd.h>

#include "options.h"

static void options_remove(int *const argc, char **const argv, const int *indices);

void
options_parse(int *const argc, char **const argv, int *const options, char **const ping_target)
{
	int ch;
	int i = 0;
	int optinds_to_remove[3] = {0};

	while ((ch = getopt(*argc, argv, ":46")) != -1) {
		switch(ch) {
		case '4':
			*options |= F_PROTOCOL_IPV4;
			optinds_to_remove[i++] = optind - 1;
			break;
		case '6':
			*options |= F_PROTOCOL_IPV6;
			optinds_to_remove[i++] = optind - 1;
			break;
		}
	}
	
	*ping_target = (optind < *argc) ? argv[*argc - 1] : NULL;

	optinds_to_remove[i] = -1;
	options_remove(argc, argv, optinds_to_remove);
	
	optreset = 1;
	optind = 1;
}

static void
options_remove(int *const argc, char **const argv, const int *indices)
{
	int i, j;
	
	for (i = j = 0; (argv[i] != NULL); i++) {
		if ((indices[j] >= 0) && (i == indices[j])) {
			j++;
		} else if (j > 0) {
			argv[i - j] = argv[i];	
		}	
	}

	*argc -= j;
	argv[i - j] = argv[i];
}
