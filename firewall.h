#ifndef FIREWALL_H_
#define FIREWALL_H_

#include "ruleset.h"
#include <linux/types.h>

// data packet
typedef struct {
	__u8 client, server, seq, state;
} packet_t;

typedef enum {
	REASON_DISALLOWED_ID = 0,
	REASON_OUT_OF_CONNECTION,
	REASON_OUT_OF_STATE,
	REASON_BAD_SEQUENCE_NUM,
	REASON_BAD_COMMAND,
	REASON_PACKET_OK
} reason_t;

// decision
typedef struct {
	char verdict;
	reason_t reason;
} decision_t;

int initRuleSet(char *filename); // initialize the firewall rule set based on the rules file - return 0 on success.
packet_t *parsePacket(char *packet); // create a new packet based on user input.
decision_t *checkPacket(packet_t packet); // check the packet against the rule set

#endif
