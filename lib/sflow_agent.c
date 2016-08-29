/* Copyright (c) 2002-2009 InMon Corp. Licensed under the terms of either the
 *   Sun Industry Standards Source License 1.1, that is available at:
 *    http://host-sflow.sourceforge.net/sissl.html
 * or the InMon sFlow License, that is available at:
 *    http://www.inmon.com/technology/sflowlicense.txt
 */

#include "sflow_api.h"
#include "util.h"

static void * sflAlloc(SFLAgent *agent, size_t bytes);
static void sflFree(SFLAgent *agent, void *obj);
static void sfl_agent_jumpTableAdd(SFLAgent *agent, SFLSampler *sampler);
static void sfl_agent_jumpTableRemove(SFLAgent *agent, SFLSampler *sampler);

/*________________--------------------------__________________
  ________________    sfl_agent_init        __________________
  ----------------__________________________------------------
*/

void sfl_agent_init(SFLAgent *agent,
		    SFLAddress *myIP, /* IP address of this agent in net byte order */
		    u_int32_t subId,  /* agent_sub_id */
		    time_t bootTime,  /* agent boot time */
		    time_t now,       /* time now */
		    void *magic,      /* ptr to pass back in logging and alloc fns */
		    allocFn_t allocFn,
		    freeFn_t freeFn,
		    errorFn_t errorFn,
		    sendFn_t sendFn)
{
    /* first clear everything */
    memset(agent, 0, sizeof(*agent));
    /* now copy in the parameters */
    agent->myIP = *myIP; /* structure copy */
    agent->subId = subId;
    agent->bootTime = bootTime;
    agent->now = now;
    agent->magic = magic;
    agent->allocFn = allocFn;
    agent->freeFn = freeFn;
    agent->errorFn = errorFn;
    agent->sendFn = sendFn;

#ifdef SFLOW_DO_SOCKET
    if(sendFn == NULL) {
	/* open the socket - really need one for v4 and another for v6? */
	if((agent->receiverSocket4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
	    sfl_agent_sysError(agent, "agent", "IPv4 socket open failed");
	if((agent->receiverSocket6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1)
	    sfl_agent_sysError(agent, "agent", "IPv6 socket open failed");
    }
#endif
}

/*_________________---------------------------__________________
  _________________   sfl_agent_release       __________________
  -----------------___________________________------------------
*/

void sfl_agent_release(SFLAgent *agent)
{
    /* release and free the samplers, pollers and receivers */
    SFLSampler *sm = agent->samplers;
    SFLPoller *pl = agent->pollers;
    SFLReceiver *rcv = agent->receivers;

    for(; sm != NULL; ) {
	SFLSampler *nextSm = sm->nxt;
	sflFree(agent, sm);
	sm = nextSm;
    }
    agent->samplers = NULL;

    for(; pl != NULL; ) {
	SFLPoller *nextPl = pl->nxt;
	sflFree(agent, pl);
	pl = nextPl;
    }
    agent->pollers = NULL;

    for(; rcv != NULL; ) {
	SFLReceiver *nextRcv = rcv->nxt;
	sflFree(agent, rcv);
	rcv = nextRcv;
    }
    agent->receivers = NULL;

#ifdef SFLOW_DO_SOCKET
    /* close the sockets */
    if(agent->receiverSocket4 > 0) close(agent->receiverSocket4);
    if(agent->receiverSocket6 > 0) close(agent->receiverSocket6);
#endif
}


/*_________________---------------------------__________________
  _________________   sfl_agent_set_*         __________________
  -----------------___________________________------------------
*/

void sfl_agent_set_agentAddress(SFLAgent *agent, SFLAddress *addr)
{
    if(addr && memcmp(addr, &agent->myIP, sizeof(agent->myIP)) != 0) {
	/* change of address */
	agent->myIP = *addr; /* structure copy */
	/* reset sequence numbers here? */
    }
}

void sfl_agent_set_agentSubId(SFLAgent *agent, u_int32_t subId)
{
    if(subId != agent->subId) {
	/* change of subId */
	agent->subId = subId;
	/* reset sequence numbers here? */
    }
}

/*_________________---------------------------__________________
  _________________   sfl_agent_tick          __________________
  -----------------___________________________------------------
*/

void sfl_agent_tick(SFLAgent *agent, time_t now)
{
    SFLReceiver *rcv = agent->receivers;
    SFLSampler *sm = agent->samplers;
    SFLPoller *pl = agent->pollers;
    agent->now = now;
    /* samplers use ticks to decide when they are sampling too fast */
    for(; sm != NULL; sm = sm->nxt) sfl_sampler_tick(sm, now);
    /* pollers use ticks to decide when to ask for counters */
    for(; pl != NULL; pl = pl->nxt) sfl_poller_tick(pl, now);
    /* receivers use ticks to flush send data.  By doing this
     * step last we ensure that fresh counters polled during
     * sfl_poller_tick() above will be flushed promptly.
     */
    for(; rcv != NULL; rcv = rcv->nxt) sfl_receiver_tick(rcv, now);
}

/*_________________---------------------------__________________
  _________________   sfl_agent_addReceiver   __________________
  -----------------___________________________------------------
*/

SFLReceiver *sfl_agent_addReceiver(SFLAgent *agent)
{
    SFLReceiver *rcv = (SFLReceiver *)sflAlloc(agent, sizeof(SFLReceiver));
    sfl_receiver_init(rcv, agent);
    /* add to end of list - to preserve the receiver index numbers for existing receivers */
    {
	SFLReceiver *r, *prev = NULL;
	for(r = agent->receivers; r != NULL; prev = r, r = r->nxt);
	if(prev) prev->nxt = rcv;
	else agent->receivers = rcv;
	rcv->nxt = NULL;
    }
    return rcv;
}

/*_________________---------------------------__________________
  _________________     sfl_dsi_compare       __________________
  -----------------___________________________------------------

  Note that if there is a mixture of ds_classes for this agent, then
  the simple numeric comparison may not be correct - the sort order (for
  the purposes of the SNMP MIB) should really be determined by the OID
  that these numeric ds_class numbers are a shorthand for.  For example,
  ds_class == 0 means ifIndex, which is the oid "1.3.6.1.2.1.2.2.1"
*/

static inline int sfl_dsi_compare(SFLDataSource_instance *pdsi1, SFLDataSource_instance *pdsi2) {
    /* could have used just memcmp(),  but not sure if that would
       give the right answer on little-endian platforms. Safer to be explicit... */
    int cmp = pdsi2->ds_class - pdsi1->ds_class;
    if(cmp == 0) cmp = pdsi2->ds_index - pdsi1->ds_index;
    if(cmp == 0) cmp = pdsi2->ds_instance - pdsi1->ds_instance;
    return cmp;
}

/*_________________---------------------------__________________
  _________________   sfl_agent_addSampler    __________________
  -----------------___________________________------------------
*/

SFLSampler *sfl_agent_addSampler(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    /* Keep the list sorted. */
    SFLSampler *prev = NULL, *sm = agent->samplers;
    for(; sm != NULL; prev = sm, sm = sm->nxt) {
	int64_t cmp = sfl_dsi_compare(pdsi, &sm->dsi);
	if(cmp == 0) return sm;  /* found - return existing one */
	if(cmp < 0) break;       /* insert here */
    }
    /* either we found the insert point, or reached the end of the list...*/

    {
	SFLSampler *newsm = (SFLSampler *)sflAlloc(agent, sizeof(SFLSampler));
	sfl_sampler_init(newsm, agent, pdsi);
	if(prev) prev->nxt = newsm;
	else agent->samplers = newsm;
	newsm->nxt = sm;

	/* see if we should go in the ifIndex jumpTable */
	if(SFL_DS_CLASS(newsm->dsi) == 0) {
	    SFLSampler *test = sfl_agent_getSamplerByIfIndex(agent, SFL_DS_INDEX(newsm->dsi));
	    if(test && (SFL_DS_INSTANCE(newsm->dsi) < SFL_DS_INSTANCE(test->dsi))) {
		/* replace with this new one because it has a lower ds_instance number */
		sfl_agent_jumpTableRemove(agent, test);
		test = NULL;
	    }
	    if(test == NULL) sfl_agent_jumpTableAdd(agent, newsm);
	}
	return newsm;
    }
}

/*_________________---------------------------__________________
  _________________   sfl_agent_addPoller     __________________
  -----------------___________________________------------------
*/

SFLPoller *sfl_agent_addPoller(SFLAgent *agent,
			       SFLDataSource_instance *pdsi,
			       void *magic,         /* ptr to pass back in getCountersFn() */
			       getCountersFn_t getCountersFn)
{
    /* keep the list sorted */
    SFLPoller *prev = NULL, *pl = agent->pollers;
    for(; pl != NULL; prev = pl, pl = pl->nxt) {
	int64_t cmp = sfl_dsi_compare(pdsi, &pl->dsi);
	if(cmp == 0) return pl;  /* found - return existing one */
	if(cmp < 0) break;       /* insert here */
    }
    /* either we found the insert point, or reached the end of the list... */
    {
	SFLPoller *newpl = (SFLPoller *)sflAlloc(agent, sizeof(SFLPoller));
	sfl_poller_init(newpl, agent, pdsi, magic, getCountersFn);
	if(prev) prev->nxt = newpl;
	else agent->pollers = newpl;
	newpl->nxt = pl;
	return newpl;
    }
}

/*_________________---------------------------__________________
  _________________  sfl_agent_removeSampler  __________________
  -----------------___________________________------------------
*/

int sfl_agent_removeSampler(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    /* find it, unlink it and free it */
    SFLSampler *prev = NULL, *sm = agent->samplers;
    for(; sm != NULL; prev = sm, sm = sm->nxt) {
	if(sfl_dsi_compare(pdsi, &sm->dsi) == 0) {
	    if(prev == NULL) agent->samplers = sm->nxt;
	    else prev->nxt = sm->nxt;
	    sfl_agent_jumpTableRemove(agent, sm);
	    sflFree(agent, sm);
	    return 1;
	}
    }
    /* not found */
    return 0;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_removePoller   __________________
  -----------------___________________________------------------
*/

int sfl_agent_removePoller(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    /* find it, unlink it and free it */
    SFLPoller *prev = NULL, *pl = agent->pollers;
    for(; pl != NULL; prev = pl, pl = pl->nxt) {
	if(sfl_dsi_compare(pdsi, &pl->dsi) == 0) {
	    if(prev == NULL) agent->pollers = pl->nxt;
	    else prev->nxt = pl->nxt;
	    sflFree(agent, pl);
	    return 1;
	}
    }
    /* not found */
    return 0;
}

/*_________________--------------------------------__________________
  _________________  sfl_agent_jumpTableAdd        __________________
  -----------------________________________________------------------
*/

static void sfl_agent_jumpTableAdd(SFLAgent *agent, SFLSampler *sampler)
{
    u_int32_t hashIndex = SFL_DS_INDEX(sampler->dsi) % SFL_HASHTABLE_SIZ;
    sampler->hash_nxt = agent->jumpTable[hashIndex];
    agent->jumpTable[hashIndex] = sampler;
}

/*_________________--------------------------------__________________
  _________________  sfl_agent_jumpTableRemove     __________________
  -----------------________________________________------------------
*/

static void sfl_agent_jumpTableRemove(SFLAgent *agent, SFLSampler *sampler)
{
    u_int32_t hashIndex = SFL_DS_INDEX(sampler->dsi) % SFL_HASHTABLE_SIZ;
    SFLSampler *search = agent->jumpTable[hashIndex], *prev = NULL;
    for( ; search != NULL; prev = search, search = search->hash_nxt) if(search == sampler) break;
    if(search) {
	// found - unlink
	if(prev) prev->hash_nxt = search->hash_nxt;
	else agent->jumpTable[hashIndex] = search->hash_nxt;
	search->hash_nxt = NULL;
    }
}

/*_________________--------------------------------__________________
  _________________  sfl_agent_getSamplerByIfIndex __________________
  -----------------________________________________------------------
  fast lookup (pointers cached in hash table).  If there are multiple
  sampler instances for a given ifIndex, then this fn will return
  the one with the lowest instance number.  Since the samplers
  list is sorted, this means the other instances will be accesible
  by following the sampler->nxt pointer (until the ds_class
  or ds_index changes).  This is helpful if you need to offer
  the same flowSample to multiple samplers.
*/

SFLSampler *sfl_agent_getSamplerByIfIndex(SFLAgent *agent, u_int32_t ifIndex)
{
    SFLSampler *search = agent->jumpTable[ifIndex % SFL_HASHTABLE_SIZ];
    for( ; search != NULL; search = search->hash_nxt) if(SFL_DS_INDEX(search->dsi) == ifIndex) break;
    return search;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_getSampler     __________________
  -----------------___________________________------------------
*/

SFLSampler *sfl_agent_getSampler(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    /* find it and return it */
    SFLSampler *sm = agent->samplers;
    for(; sm != NULL; sm = sm->nxt)
	if(sfl_dsi_compare(pdsi, &sm->dsi) == 0) return sm;
    /* not found */
    return NULL;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_getPoller      __________________
  -----------------___________________________------------------
*/

SFLPoller *sfl_agent_getPoller(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    /* find it and return it */
    SFLPoller *pl = agent->pollers;
    for(; pl != NULL; pl = pl->nxt)
	if(sfl_dsi_compare(pdsi, &pl->dsi) == 0) return pl;
    /* not found */
    return NULL;
}

/*_________________-----------------------------------__________________
  _________________  sfl_agent_getPollerByBridgePort  __________________
  -----------------___________________________________------------------
*/

SFLPoller *sfl_agent_getPollerByBridgePort(SFLAgent *agent, uint32_t port_no)
{
  /* find it and return it */
    SFLPoller *pl = agent->pollers;
    for(; pl != NULL; pl = pl->nxt)
	if(pl->bridgePort == port_no) return pl;
    /* not found */
    return NULL;
}

/*_________________---------------------------__________________
  _________________  sfl_agent_getReceiver    __________________
  -----------------___________________________------------------
*/

SFLReceiver *sfl_agent_getReceiver(SFLAgent *agent, u_int32_t receiverIndex)
{
    u_int32_t rcvIdx = 0;
    SFLReceiver *rcv = agent->receivers;
    for(;  rcv != NULL; rcv = rcv->nxt)
	if(receiverIndex == ++rcvIdx) return rcv;

    /* not found - ran off the end of the table */
    return NULL;
}

/*_________________---------------------------__________________
  _________________ sfl_agent_getNextSampler  __________________
  -----------------___________________________------------------
*/

SFLSampler *sfl_agent_getNextSampler(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    /* return the one lexograpically just after it - assume they are sorted
       correctly according to the lexographical ordering of the object ids */
    SFLSampler *sm = sfl_agent_getSampler(agent, pdsi);
    return sm ? sm->nxt : NULL;
}

/*_________________---------------------------__________________
  _________________ sfl_agent_getNextPoller   __________________
  -----------------___________________________------------------
*/

SFLPoller *sfl_agent_getNextPoller(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    /* return the one lexograpically just after it - assume they are sorted
       correctly according to the lexographical ordering of the object ids */
    SFLPoller *pl = sfl_agent_getPoller(agent, pdsi);
    return pl ? pl->nxt : NULL;
}

/*_________________---------------------------__________________
  _________________ sfl_agent_getNextReceiver __________________
  -----------------___________________________------------------
*/

SFLReceiver *sfl_agent_getNextReceiver(SFLAgent *agent, u_int32_t receiverIndex)
{
    return sfl_agent_getReceiver(agent, receiverIndex + 1);
}


/*_________________---------------------------__________________
  _________________ sfl_agent_resetReceiver   __________________
  -----------------___________________________------------------
*/

void sfl_agent_resetReceiver(SFLAgent *agent, SFLReceiver *receiver)
{
    /* tell samplers and pollers to stop sending to this receiver */
    /* first get his receiverIndex */
    u_int32_t rcvIdx = 0;
    SFLReceiver *rcv = agent->receivers;
    for(; rcv != NULL; rcv = rcv->nxt) {
	rcvIdx++; /* thanks to Diego Valverde for pointing out this bugfix */
	if(rcv == receiver) {
	    /* now tell anyone that is using it to stop */
	    SFLSampler *sm = agent->samplers;
	    SFLPoller *pl = agent->pollers;

	    for(; sm != NULL; sm = sm->nxt)
		if(sfl_sampler_get_sFlowFsReceiver(sm) == rcvIdx) sfl_sampler_set_sFlowFsReceiver(sm, 0);

	    for(; pl != NULL; pl = pl->nxt)
		if(sfl_poller_get_sFlowCpReceiver(pl) == rcvIdx) sfl_poller_set_sFlowCpReceiver(pl, 0);

	    break;
	}
    }
}

/*_________________---------------------------__________________
  _________________     sfl_agent_error       __________________
  -----------------___________________________------------------
*/
#define MAX_ERRMSG_LEN 1000

void sfl_agent_error(SFLAgent *agent, char *modName, char *msg)
{
    char errm[MAX_ERRMSG_LEN];
    snprintf(errm, sizeof errm, "sfl_agent_error: %s: %s\n", modName, msg);
    if(agent->errorFn) (*agent->errorFn)(agent->magic, agent, errm);
    else {
	fprintf(stderr, "%s\n", errm);
	fflush(stderr);
    }
}

/*_________________---------------------------__________________
  _________________     sfl_agent_sysError    __________________
  -----------------___________________________------------------
*/

void sfl_agent_sysError(SFLAgent *agent, char *modName, char *msg)
{
    char errm[MAX_ERRMSG_LEN];
    snprintf(errm, sizeof errm, "sfl_agent_sysError: %s: %s (errno = %d - %s)\n", modName, msg, errno, ovs_strerror(errno));
    if(agent->errorFn) (*agent->errorFn)(agent->magic, agent, errm);
    else {
	fprintf(stderr, "%s\n", errm);
	fflush(stderr);
    }
}


/*_________________---------------------------__________________
  _________________       alloc and free      __________________
  -----------------___________________________------------------
*/

static void * sflAlloc(SFLAgent *agent, size_t bytes)
{
    if(agent->allocFn) return (*agent->allocFn)(agent->magic, agent, bytes);
    else return SFL_ALLOC(bytes);
}

static void sflFree(SFLAgent *agent, void *obj)
{
    if(agent->freeFn) (*agent->freeFn)(agent->magic, agent, obj);
    else SFL_FREE(obj);
}
