/* Copyright (c) 2002-2009 InMon Corp. Licensed under the terms of either the
 *   Sun Industry Standards Source License 1.1, that is available at:
 *    http://host-sflow.sourceforge.net/sissl.html
 * or the InMon sFlow License, that is available at:
 *    http://www.inmon.com/technology/sflowlicense.txt
 */

#ifndef SFLOW_API_H
#define SFLOW_API_H 1

/* define SFLOW_DO_SOCKET to 1 if you want the agent
   to send the packets itself, otherwise set the sendFn
   callback in sfl_agent_init.*/
/* #define SFLOW_DO_SOCKET */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h> /* for htonl */

#ifdef SFLOW_DO_SOCKET
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#endif

#include "sflow.h"

/* define SFLOW_SOFTWARE_SAMPLING to 1 if you need to use the
   sfl_sampler_takeSample routine and give it every packet */
/* #define SFLOW_SOFTWARE_SAMPLING */

/*
  uncomment this preprocessor flag  (or compile with -DSFL_USE_32BIT_INDEX)
  if your ds_index numbers can ever be >= 2^30-1 (i.e. >= 0x3FFFFFFF)
*/
/* #define SFL_USE_32BIT_INDEX */


/* Used to combine ds_class, ds_index and instance into
   a single 64-bit number like this:
   __________________________________
   | cls|  index     |   instance     |
   ----------------------------------

   but now is opened up to a 12-byte struct to ensure
   that ds_index has a full 32-bit field, and to make
   accessing the components simpler. The macros have
   the same behavior as before, so this change should
   be transparent.  The only difference is that these
   objects are now passed around by reference instead
   of by value, and the comparison is done using a fn.
*/

typedef struct _SFLDataSource_instance {
    u_int32_t ds_class;
    u_int32_t ds_index;
    u_int32_t ds_instance;
} SFLDataSource_instance;

#ifdef SFL_USE_32BIT_INDEX
#define SFL_FLOW_SAMPLE_TYPE SFLFlow_sample_expanded
#define SFL_COUNTERS_SAMPLE_TYPE SFLCounters_sample_expanded
#else
#define SFL_FLOW_SAMPLE_TYPE SFLFlow_sample
#define SFL_COUNTERS_SAMPLE_TYPE SFLCounters_sample
/* if index numbers are not going to use all 32 bits, then we can use
   the more compact encoding, with the dataSource class and index merged */
#define SFL_DS_DATASOURCE(dsi) (((dsi).ds_class << 24) + (dsi).ds_index)
#endif

#define SFL_DS_INSTANCE(dsi) (dsi).ds_instance
#define SFL_DS_CLASS(dsi) (dsi).ds_class
#define SFL_DS_INDEX(dsi) (dsi).ds_index
#define SFL_DS_SET(dsi,clss,indx,inst)		\
    do {					\
	(dsi).ds_class = (clss);		\
	(dsi).ds_index = (indx);		\
	(dsi).ds_instance = (inst);		\
    } while(0)

typedef struct _SFLSampleCollector {
    u_int32_t data[(SFL_MAX_DATAGRAM_SIZE + SFL_DATA_PAD) / sizeof(u_int32_t)];
    u_int32_t *datap; /* packet fill pointer */
    u_int32_t pktlen; /* accumulated size */
    u_int32_t packetSeqNo;
    u_int32_t numSamples;
} SFLSampleCollector;

struct _SFLAgent;  /* forward decl */

typedef struct _SFLReceiver {
    struct _SFLReceiver *nxt;
    /* MIB fields */
    char *sFlowRcvrOwner;
    time_t sFlowRcvrTimeout;
    u_int32_t sFlowRcvrMaximumDatagramSize;
    SFLAddress sFlowRcvrAddress;
    u_int32_t sFlowRcvrPort;
    u_int32_t sFlowRcvrDatagramVersion;
    /* public fields */
    struct _SFLAgent *agent;    /* pointer to my agent */
    /* private fields */
    SFLSampleCollector sampleCollector;
#ifdef SFLOW_DO_SOCKET
    struct sockaddr_in receiver4;
    struct sockaddr_in6 receiver6;
#endif
} SFLReceiver;

typedef struct _SFLSampler {
    /* for linked list */
    struct _SFLSampler *nxt;
    /* for hash lookup table */
    struct _SFLSampler *hash_nxt;
    /* MIB fields */
    SFLDataSource_instance dsi;
    u_int32_t sFlowFsReceiver;
    u_int32_t sFlowFsPacketSamplingRate;
    u_int32_t sFlowFsMaximumHeaderSize;
    /* public fields */
    struct _SFLAgent *agent; /* pointer to my agent */
    /* private fields */
    SFLReceiver *myReceiver;
    u_int32_t skip;
    u_int32_t samplePool;
    u_int32_t flowSampleSeqNo;
    /* rate checking */
    u_int32_t samplesThisTick;
    u_int32_t samplesLastTick;
    u_int32_t backoffThreshold;
} SFLSampler;

/* declare */
struct _SFLPoller;

typedef void (*getCountersFn_t)(void *magic,                   /* callback to get counters */
				struct _SFLPoller *sampler,    /* called with self */
				SFL_COUNTERS_SAMPLE_TYPE *cs); /* struct to fill in */

typedef struct _SFLPoller {
    /* for linked list */
    struct _SFLPoller *nxt;
    /* MIB fields */
    SFLDataSource_instance dsi;
    u_int32_t sFlowCpReceiver;
    time_t sFlowCpInterval;
    /* public fields */
    struct _SFLAgent *agent; /* pointer to my agent */
    void *magic;             /* ptr to pass back in getCountersFn() */
    getCountersFn_t getCountersFn;
    u_int32_t bridgePort; /* port number local to bridge */
    /* private fields */
    SFLReceiver *myReceiver;
    time_t countersCountdown;
    u_int32_t countersSampleSeqNo;
} SFLPoller;

typedef void *(*allocFn_t)(void *magic,               /* callback to allocate space on heap */
			   struct _SFLAgent *agent,   /* called with self */
			   size_t bytes);             /* bytes requested */

typedef int (*freeFn_t)(void *magic,                  /* callback to free space on heap */
			struct _SFLAgent *agent,      /* called with self */
			void *obj);                   /* obj to free */

typedef void (*errorFn_t)(void *magic,                /* callback to log error message */
			  struct _SFLAgent *agent,    /* called with self */
			  char *msg);                 /* error message */

typedef void (*sendFn_t)(void *magic,                 /* optional override fn to send packet */
			 struct _SFLAgent *agent,
			 SFLReceiver *receiver,
			 u_char *pkt,
			 u_int32_t pktLen);


/* prime numbers are good for hash tables */
#define SFL_HASHTABLE_SIZ 199

typedef struct _SFLAgent {
    SFLSampler *jumpTable[SFL_HASHTABLE_SIZ]; /* fast lookup table for samplers (by ifIndex) */
    SFLSampler *samplers;   /* the list of samplers */
    SFLPoller  *pollers;    /* the list of samplers */
    SFLReceiver *receivers; /* the array of receivers */
    time_t bootTime;        /* time when we booted or started */
    time_t now;             /* time now */
    SFLAddress myIP;        /* IP address of this node */
    u_int32_t subId;        /* sub_agent_id */
    void *magic;            /* ptr to pass back in logging and alloc fns */
    allocFn_t allocFn;
    freeFn_t freeFn;
    errorFn_t errorFn;
    sendFn_t sendFn;
#ifdef SFLOW_DO_SOCKET
    int receiverSocket4;
    int receiverSocket6;
#endif
} SFLAgent;

/* call this at the start with a newly created agent */
void sfl_agent_init(SFLAgent *agent,
		    SFLAddress *myIP, /* IP address of this agent */
		    u_int32_t subId,  /* agent_sub_id */
		    time_t bootTime,  /* agent boot time */
		    time_t now,       /* time now */
		    void *magic,      /* ptr to pass back in logging and alloc fns */
		    allocFn_t allocFn,
		    freeFn_t freeFn,
		    errorFn_t errorFn,
		    sendFn_t sendFn);

/* call this to create samplers */
SFLSampler *sfl_agent_addSampler(SFLAgent *agent, SFLDataSource_instance *pdsi);

/* call this to create pollers */
SFLPoller *sfl_agent_addPoller(SFLAgent *agent,
			       SFLDataSource_instance *pdsi,
			       void *magic, /* ptr to pass back in getCountersFn() */
			       getCountersFn_t getCountersFn);

/* call this to create receivers */
SFLReceiver *sfl_agent_addReceiver(SFLAgent *agent);

/* call this to remove samplers */
int sfl_agent_removeSampler(SFLAgent *agent, SFLDataSource_instance *pdsi);

/* call this to remove pollers */
int sfl_agent_removePoller(SFLAgent *agent, SFLDataSource_instance *pdsi);

/* note: receivers should not be removed. Typically the receivers
   list will be created at init time and never changed */

/* call these fns to retrieve sampler, poller or receiver (e.g. for SNMP GET or GETNEXT operation) */
SFLSampler  *sfl_agent_getSampler(SFLAgent *agent, SFLDataSource_instance *pdsi);
SFLSampler  *sfl_agent_getNextSampler(SFLAgent *agent, SFLDataSource_instance *pdsi);
SFLPoller   *sfl_agent_getPoller(SFLAgent *agent, SFLDataSource_instance *pdsi);
SFLPoller   *sfl_agent_getNextPoller(SFLAgent *agent, SFLDataSource_instance *pdsi);
SFLReceiver *sfl_agent_getReceiver(SFLAgent *agent, u_int32_t receiverIndex);
SFLReceiver *sfl_agent_getNextReceiver(SFLAgent *agent, u_int32_t receiverIndex);

/* jump table access - for performance */
SFLSampler *sfl_agent_getSamplerByIfIndex(SFLAgent *agent, u_int32_t ifIndex);

/* call these functions to GET and SET MIB values */

/* receiver */
char *      sfl_receiver_get_sFlowRcvrOwner(SFLReceiver *receiver);
void        sfl_receiver_set_sFlowRcvrOwner(SFLReceiver *receiver, char *sFlowRcvrOwner);
time_t      sfl_receiver_get_sFlowRcvrTimeout(SFLReceiver *receiver);
void        sfl_receiver_set_sFlowRcvrTimeout(SFLReceiver *receiver, time_t sFlowRcvrTimeout);
u_int32_t   sfl_receiver_get_sFlowRcvrMaximumDatagramSize(SFLReceiver *receiver);
void        sfl_receiver_set_sFlowRcvrMaximumDatagramSize(SFLReceiver *receiver, u_int32_t sFlowRcvrMaximumDatagramSize);
SFLAddress *sfl_receiver_get_sFlowRcvrAddress(SFLReceiver *receiver);
void        sfl_receiver_set_sFlowRcvrAddress(SFLReceiver *receiver, SFLAddress *sFlowRcvrAddress);
u_int32_t   sfl_receiver_get_sFlowRcvrPort(SFLReceiver *receiver);
void        sfl_receiver_set_sFlowRcvrPort(SFLReceiver *receiver, u_int32_t sFlowRcvrPort);
/* sampler */
u_int32_t sfl_sampler_get_sFlowFsReceiver(SFLSampler *sampler);
void      sfl_sampler_set_sFlowFsReceiver(SFLSampler *sampler, u_int32_t sFlowFsReceiver);
u_int32_t sfl_sampler_get_sFlowFsPacketSamplingRate(SFLSampler *sampler);
void      sfl_sampler_set_sFlowFsPacketSamplingRate(SFLSampler *sampler, u_int32_t sFlowFsPacketSamplingRate);
u_int32_t sfl_sampler_get_sFlowFsMaximumHeaderSize(SFLSampler *sampler);
void      sfl_sampler_set_sFlowFsMaximumHeaderSize(SFLSampler *sampler, u_int32_t sFlowFsMaximumHeaderSize);
u_int32_t sfl_sampler_get_samplesLastTick(SFLSampler *sampler);
/* poller */
u_int32_t sfl_poller_get_sFlowCpReceiver(SFLPoller *poller);
void      sfl_poller_set_sFlowCpReceiver(SFLPoller *poller, u_int32_t sFlowCpReceiver);
u_int32_t sfl_poller_get_sFlowCpInterval(SFLPoller *poller);
void      sfl_poller_set_sFlowCpInterval(SFLPoller *poller, u_int32_t sFlowCpInterval);

/* fns to set the sflow agent address or sub-id */
void sfl_agent_set_agentAddress(SFLAgent *agent, SFLAddress *addr);
void sfl_agent_set_agentSubId(SFLAgent *agent, u_int32_t subId);

/* The poller may need a separate number to reference the local bridge port
   to get counters if it is not the same as the global ifIndex */
void sfl_poller_set_bridgePort(SFLPoller *poller, u_int32_t port_no);
u_int32_t sfl_poller_get_bridgePort(SFLPoller *poller);
SFLPoller *sfl_agent_getPollerByBridgePort(SFLAgent *agent, u_int32_t port_no);

/* call this to indicate a discontinuity with a counter like samplePool so that the
   sflow collector will ignore the next delta */
void sfl_sampler_resetFlowSeqNo(SFLSampler *sampler);

/* call this to indicate a discontinuity with one or more of the counters so that the
   sflow collector will ignore the next delta */
void sfl_poller_resetCountersSeqNo(SFLPoller *poller);

#ifdef SFLOW_SOFTWARE_SAMLING
/* software sampling: call this with every packet - returns non-zero if the packet
   should be sampled (in which case you then call sfl_sampler_writeFlowSample()) */
int sfl_sampler_takeSample(SFLSampler *sampler);
#endif

/* call this to set a maximum samples-per-second threshold. If the sampler reaches this
   threshold it will automatically back off the sampling rate. A value of 0 disables the
   mechanism */
void sfl_sampler_set_backoffThreshold(SFLSampler *sampler, u_int32_t samplesPerSecond);
u_int32_t sfl_sampler_get_backoffThreshold(SFLSampler *sampler);

/* call this once per second (N.B. not on interrupt stack i.e. not hard real-time) */
void sfl_agent_tick(SFLAgent *agent, time_t now);

/* call this with each flow sample */
void sfl_sampler_writeFlowSample(SFLSampler *sampler, SFL_FLOW_SAMPLE_TYPE *fs);

/* call this to push counters samples (usually done in the getCountersFn callback) */
void sfl_poller_writeCountersSample(SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs);

/* call this to deallocate resources */
void sfl_agent_release(SFLAgent *agent);


/* internal fns */

void sfl_receiver_init(SFLReceiver *receiver, SFLAgent *agent);
void sfl_sampler_init(SFLSampler *sampler, SFLAgent *agent, SFLDataSource_instance *pdsi);
void sfl_poller_init(SFLPoller *poller, SFLAgent *agent, SFLDataSource_instance *pdsi, void *magic, getCountersFn_t getCountersFn);


void sfl_receiver_tick(SFLReceiver *receiver, time_t now);
void sfl_poller_tick(SFLPoller *poller, time_t now);
void sfl_sampler_tick(SFLSampler *sampler, time_t now);

int sfl_receiver_writeFlowSample(SFLReceiver *receiver, SFL_FLOW_SAMPLE_TYPE *fs);
int sfl_receiver_writeCountersSample(SFLReceiver *receiver, SFL_COUNTERS_SAMPLE_TYPE *cs);

void sfl_agent_resetReceiver(SFLAgent *agent, SFLReceiver *receiver);

void sfl_agent_error(SFLAgent *agent, char *modName, char *msg);
void sfl_agent_sysError(SFLAgent *agent, char *modName, char *msg);

u_int32_t sfl_receiver_samplePacketsSent(SFLReceiver *receiver);

#define SFL_ALLOC malloc
#define SFL_FREE free

#endif /* SFLOW_API_H */


