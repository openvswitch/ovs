/*
 * Copyright (c) 2016 6WIND S.A.
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

#ifndef COLORS_H
#define COLORS_H 1

#include <stdbool.h>

struct colors {
    /* Color codes for various situation. Each of these is a fully formed
     * Select Graphic Rendition (SGR, "\33[...m") start string for the
     * appropriate color.
     */
    char *actions;
    char *drop;
    char *learn;
    char *param;
    char *paren;
    char *special;
    char *value;

    /* SGR end string. */
    char *end;
};
extern struct colors colors;

void colors_init(bool enable_color);

#endif /* colors.h */
