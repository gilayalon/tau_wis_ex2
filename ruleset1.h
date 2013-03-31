#ifndef RULESET_H_
#define RULESET_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>

// rule
typedef struct {
	__u8 client_min_id, client_max_id;
	__u8 server_min_id, server_max_id;
	__u8 verdict;
	__u8 padding[3];
	rule_t *prev;
	rule_t *next;
} rule_t;

// rule set
typedef struct
{
	rule_t *head;
	rule_t *tail;
} ruleset_t;

__u8 *unpack(__u64 p, int k);
rule_t *createNewRule(__u64 segment);
ruleset_t *initRuleSet();
rule_t *addNewRule(ruleset_t ruleset, __u64 segment); // add a new rule to the firewall rule set.
void clearRuleSet(rule_t *first);
int isEmpty(ruleset_t ruleset);

#endif
