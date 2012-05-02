/*
 * Copyright (c) 2010, 2011 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef STRESS_H
#define STRESS_H 1

#include <stdbool.h>

struct stress_option {
    /* Properties. */
    char *name;                 /* Short identifier string */
    char *description;          /* Description of what the option stresses. */
    unsigned int recommended;   /* Recommended period. */
    unsigned int min;           /* Minimum period that can be set. */
    unsigned int max;           /* Maximum period that can be set. */
    unsigned int def;           /* Default value. */

    /* Configuration. */
    unsigned int period;        /* Desired period for firing, 0 to disable. */
    bool random;                /* Fire randomly or exactly at period? */

    /* State. */
    unsigned int counter;       /* Number of hits before next firing. */
    unsigned long long int hits; /* Hits since last reset. */
};

/* Creates and initializes a global instance of a stress option.
 *
 * NAME is a single word descriptive identifier for the option.  This is the
 * token to pass in to the STRESS() macro at the sites where exectution is to
 * be controlled by the option.
 *
 * DESCRIPTION is a quoted string that should describe to a person unfamiliar
 * with the detailed internals of the code what behavior the option affects.
 *
 * RECOMMENDED is a suggested value for a person unfamiliar with the internals.
 * It should put reasonable stress on the system without crippling it.
 *
 * MIN and MAX are the minimum and maximum values allowed for the option.
 *
 * DEFAULT is the default value for the option.  Specify 0 to disable the
 * option by default, which should be the usual choice.  But some options can
 * be left on at low levels without noticable impact to the end user.  An
 * example would be failing to allocate a buffer for every 100000th packet
 * processed by the system.
 */
#if USE_LINKER_SECTIONS
#define STRESS_OPTION(NAME, DESCRIPTION, RECOMMENDED, MIN, MAX, DEFAULT) \
        STRESS_OPTION__(NAME, DESCRIPTION, RECOMMENDED, MIN, MAX, DEFAULT); \
        extern struct stress_option *stress_option_ptr_##NAME;          \
        struct stress_option *stress_option_ptr_##NAME                  \
            __attribute__((section("stress_options"))) = &stress_##NAME
#else
#define STRESS_OPTION(NAME, DESCRIPTION, RECOMMENDED, MIN, MAX, DEFAULT) \
        extern struct stress_option stress_##NAME
#endif

/* Yields true if stress option NAME should be triggered,
 * false otherwise. */
#define STRESS(NAME) stress_sample__(&stress_##NAME)

void stress_init_command(void);

/* Implementation details. */

#define STRESS_OPTION__(NAME, DESCRIPTION, RECOMMENDED, MIN, MAX, DEFAULT) \
        extern struct stress_option stress_##NAME;                      \
        struct stress_option stress_##NAME =                            \
        { #NAME, DESCRIPTION, RECOMMENDED, MIN, MAX, DEFAULT,           \
          DEFAULT ? DEFAULT : 0,                /* period */            \
          false,                                /* random */            \
          UINT_MAX,                             /* counter */           \
          0 }                                   /* hits */

bool stress_sample_slowpath__(struct stress_option *);
static inline bool stress_sample__(struct stress_option *option)
{
    return --option->counter == 0 && stress_sample_slowpath__(option);
}

#endif /* STRESS_H */
