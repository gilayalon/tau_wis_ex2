#include "ruleset1.h"
#include <limits.h>

__u8 *unpack(__u64 p, int k) {
	unsigned  mask = 0xFF;
	__u64 n = k * CHAR_BIT;

    mask <<= n;
	return &( ( p & mask ) >> n );
}


rule_t *createNewRule(__u64 segment) {
	rule_t *result;

	result = (rule_t *)malloc(sizeof(rule_t));

	if (result != NULL) {
		result->client_min_id = *unpack(segment, 0); // ---------------------
		result->client_max_id = *unpack(segment, 1); //-----------------------
		result->server_min_id = *unpack(segment, 2);//--------------------
		result->server_max_id = *unpack(segment, 3);//-------------------
		result->verdict = *unpack(segment, 4);//--------------------
		result->padding = unpack(segment, 5);//-----------------
		result->next = NULL;
		result->prev = NULL;
	} else {
		perror ("Error: standard function malloc has failed\n");
	}

	return result;
}

ruleset_t *initRuleSet() {
	ruleset_t *result;
	__u64 l = 0; //-------------------------

	result = (ruleset_t *)malloc(sizeof(ruleset_t));

	if (result != NULL) {
		result->head = createNewRule(l); //----------------
		if (result->head == NULL)
			return NULL;
		result->tail = createNewRule(l); //------------------
		if (result->tail == NULL)
			return NULL;
		result->head->next = result->tail;
		result->tail->prev = result->head;
	} else {
		perror ("Error: standard function malloc has failed\n");
	}

	return result;
}


rule_t *addNewRule(ruleset_t ruleset, __u64 segment) { // add a new rule to the firewall rule set.

	*newRule = createNewRule(segment);

	newRule->next = ruleset->head->next; //------------ adding to the top of the list?
	newRule->prev = ruleset->head;
	ruleset->head->next->prev = newRule;
	ruleset->head->next = newRule;
}

void clearRuleSet(rule_t *first) {
	if (first != NULL) {
		deleteList(first->next);
		free(first);
	}
}

int isEmpty(ruleset_t ruleset); //-------------- do we need this?

