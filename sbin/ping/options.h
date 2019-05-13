#ifndef OPTIONS_H
#define OPTIONS_H 1

#define F_PROTOCOL_IPV4  0x10000000
#define F_PROTOCOL_IPV6  0x20000000

void options_parse(int *const argc, char **const argv, int *const options, char **const ping_target);

#endif	/* OPTIONS_H */
