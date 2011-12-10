/* Copyright (c) 2002-2009 InMon Corp. Licensed under the terms of either the
 *   Sun Industry Standards Source License 1.1, that is available at:
 *    http://host-sflow.sourceforge.net/sissl.html
 * or the InMon sFlow License, that is available at:
 *    http://www.inmon.com/technology/sflowlicense.txt
 */

#include "sflow_api.h"


/*_________________--------------------------__________________
  _________________   sfl_sampler_init       __________________
  -----------------__________________________------------------
*/

void sfl_sampler_init(SFLSampler *sampler, SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    /* copy the dsi in case it points to sampler->dsi, which we are about to clear.
       (Thanks to Jagjit Choudray of Force 10 Networks for pointing out this bug) */
    SFLDataSource_instance dsi = *pdsi;

    /* preserve the *nxt pointer too, in case we are resetting this poller and it is
       already part of the agent's linked list (thanks to Matt Woodly for pointing this out,
       and to Andy Kitchingman for pointing out that it applies to the hash_nxt ptr too) */
    SFLSampler *nxtPtr = sampler->nxt;
    SFLSampler *hashPtr = sampler->hash_nxt;

    /* clear everything */
    memset(sampler, 0, sizeof(*sampler));

    /* restore the linked list and hash-table ptr */
    sampler->nxt = nxtPtr;
    sampler->hash_nxt = hashPtr;

    /* now copy in the parameters */
    sampler->agent = agent;
    sampler->dsi = dsi;

    /* set defaults */
    sampler->sFlowFsMaximumHeaderSize = SFL_DEFAULT_HEADER_SIZE;
    sampler->sFlowFsPacketSamplingRate = SFL_DEFAULT_SAMPLING_RATE;
}

/*_________________--------------------------__________________
  _________________       reset              __________________
  -----------------__________________________------------------
*/

static void reset(SFLSampler *sampler)
{
    SFLDataSource_instance dsi = sampler->dsi;
    sfl_sampler_init(sampler, sampler->agent, &dsi);
}

/*_________________---------------------------__________________
  _________________      MIB access           __________________
  -----------------___________________________------------------
*/
u_int32_t sfl_sampler_get_sFlowFsReceiver(SFLSampler *sampler) {
    return sampler->sFlowFsReceiver;
}
void sfl_sampler_set_sFlowFsReceiver(SFLSampler *sampler, u_int32_t sFlowFsReceiver) {
    sampler->sFlowFsReceiver = sFlowFsReceiver;
    if(sFlowFsReceiver == 0) reset(sampler);
    else {
	/* retrieve and cache a direct pointer to my receiver */
	sampler->myReceiver = sfl_agent_getReceiver(sampler->agent, sampler->sFlowFsReceiver);
    }
}
u_int32_t sfl_sampler_get_sFlowFsPacketSamplingRate(SFLSampler *sampler) {
    return sampler->sFlowFsPacketSamplingRate;
}
void sfl_sampler_set_sFlowFsPacketSamplingRate(SFLSampler *sampler, u_int32_t sFlowFsPacketSamplingRate) {
    sampler->sFlowFsPacketSamplingRate = sFlowFsPacketSamplingRate;
}
u_int32_t sfl_sampler_get_sFlowFsMaximumHeaderSize(SFLSampler *sampler) {
    return sampler->sFlowFsMaximumHeaderSize;
}
void sfl_sampler_set_sFlowFsMaximumHeaderSize(SFLSampler *sampler, u_int32_t sFlowFsMaximumHeaderSize) {
    sampler->sFlowFsMaximumHeaderSize = sFlowFsMaximumHeaderSize;
}

/* call this to set a maximum samples-per-second threshold. If the sampler reaches this
   threshold it will automatically back off the sampling rate. A value of 0 disables the
   mechanism */
void sfl_sampler_set_backoffThreshold(SFLSampler *sampler, u_int32_t samplesPerSecond) {
    sampler->backoffThreshold = samplesPerSecond;
}
u_int32_t sfl_sampler_get_backoffThreshold(SFLSampler *sampler) {
    return sampler->backoffThreshold;
}
u_int32_t sfl_sampler_get_samplesLastTick(SFLSampler *sampler) {
    return sampler->samplesLastTick;
}

/*_________________---------------------------------__________________
  _________________   sequence number reset         __________________
  -----------------_________________________________------------------
  Used by the agent to indicate a samplePool discontinuity
  so that the sflow collector will know to ignore the next delta.
*/
void sfl_sampler_resetFlowSeqNo(SFLSampler *sampler) { sampler->flowSampleSeqNo = 0; }


/*_________________---------------------------__________________
  _________________    sfl_sampler_tick       __________________
  -----------------___________________________------------------
*/

void sfl_sampler_tick(SFLSampler *sampler, time_t now)
{
    if(sampler->backoffThreshold && sampler->samplesThisTick > sampler->backoffThreshold) {
	/* automatic backoff.  If using hardware sampling then this is where you have to
	 * call out to change the sampling rate and make sure that any other registers/variables
	 * that hold this value are updated.
	 */
	sampler->sFlowFsPacketSamplingRate *= 2;
    }
    sampler->samplesLastTick = sampler->samplesThisTick;
    sampler->samplesThisTick = 0;
}



/*_________________------------------------------__________________
  _________________ sfl_sampler_writeFlowSample  __________________
  -----------------______________________________------------------
*/

void sfl_sampler_writeFlowSample(SFLSampler *sampler, SFL_FLOW_SAMPLE_TYPE *fs)
{
    if(fs == NULL) return;
    sampler->samplesThisTick++;
    /* increment the sequence number */
    fs->sequence_number = ++sampler->flowSampleSeqNo;
    /* copy the other header fields in */
#ifdef SFL_USE_32BIT_INDEX
    fs->ds_class = SFL_DS_CLASS(sampler->dsi);
    fs->ds_index = SFL_DS_INDEX(sampler->dsi);
#else
    fs->source_id = SFL_DS_DATASOURCE(sampler->dsi);
#endif
    /* the sampling rate may have been set already. */
    if(fs->sampling_rate == 0) fs->sampling_rate = sampler->sFlowFsPacketSamplingRate;
    /* the samplePool may be maintained upstream too. */
    if( fs->sample_pool == 0) fs->sample_pool = sampler->samplePool;
    /* sent to my receiver */
    if(sampler->myReceiver) sfl_receiver_writeFlowSample(sampler->myReceiver, fs);
}

#ifdef SFLOW_SOFTWARE_SAMPLING

/* ================== software sampling ========================*/

/*_________________---------------------------__________________
  _________________     nextRandomSkip        __________________
  -----------------___________________________------------------
*/

inline static u_int32_t nextRandomSkip(u_int32_t mean)
{
    if(mean == 0 || mean == 1) return 1;
    return ((random() % ((2 * mean) - 1)) + 1);
}

/*_________________---------------------------__________________
  _________________  sfl_sampler_takeSample   __________________
  -----------------___________________________------------------
*/

int sfl_sampler_takeSample(SFLSampler *sampler)
{
    if(sampler->skip == 0) {
	/* first time - seed the random number generator */
	srandom(SFL_DS_INDEX(sampler->dsi));
	sampler->skip = nextRandomSkip(sampler->sFlowFsPacketSamplingRate);
    }

    /* increment the samplePool */
    sampler->samplePool++;

    if(--sampler->skip == 0) {
	/* reached zero. Set the next skip and return true. */
	sampler->skip = nextRandomSkip(sampler->sFlowFsPacketSamplingRate);
	return 1;
    }
    return 0;
}

#endif /* SFLOW_SOFTWARE_SAMPLING */
