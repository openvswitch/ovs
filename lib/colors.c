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

/* Handle color setup for output. */

#include <config.h>

#include "colors.h"

#include <stdlib.h>
#include <string.h>

#include "util.h"

struct color_key {
    const char *name;
    char **var_ptr;
};

/* Returns a pointer to the variable containing a given color. */
static char **get_color(const struct color_key color_dic[], const char * name);

/* Extract user-defined colors from OVS_COLORS environment variable. */
static void colors_parse_from_env(const struct color_key color_dic[]);

/* Global holder for colors. Declared in header file. */
struct colors colors = { "", "", "", "", "", "", "", "" };

static char **
get_color(const struct color_key color_dic[], const char *name)
{
    const struct color_key *color;
    for (color = color_dic; color->name; color++) {
        if (!strcmp(color->name, name)) {
            return color->var_ptr;
        }
    }
    return NULL;
}

void
colors_init(bool enable_color)
{
    /* If colored output is not enabled, just keep empty strings for color
     * markers, including end marker.
     */
    if (!enable_color) {
        return;
    }

    /* Color IDs to use in OVS_COLORS environment variable to overwrite
     * defaults with custom colors.
     */
    const struct color_key color_dic[] = {
        { "ac", &colors.actions },
        { "dr", &colors.drop },
        { "le", &colors.learn },
        { "pm", &colors.param },
        { "pr", &colors.paren },
        { "sp", &colors.special },
        { "vl", &colors.value },
        { NULL, NULL }
    };

    /* Actual color to use. First we define default values. */
    colors.actions = "\33[1;31m\33[K";  /* bold red */
    colors.drop    = "\33[34m\33[K";    /* blue */
    colors.learn   = "\33[31m\33[K";    /* red */
    colors.param   = "\33[36m\33[K";    /* cyan */
    colors.paren   = "\33[35m\33[K";    /* magenta */
    colors.special = "\33[33m\33[K";    /* yellow */
    colors.value   = "\33[32m\33[K";    /* green */
    colors.end     = "\33[m\33[K";      /* end marker */

    /* Now, overwrite with user-defined color markers. */
    colors_parse_from_env(color_dic);
}

/* Colorized output: get user-defined colors from OVS_COLORS environment
 * variable. This must be a string of the form:
 *     ac=01;31:r=34:le=:pm=02;32:pr=01;30
 * (see color_dic[] in colors_init() function for all color names)
 * If a color is missing from this string, default value is used instead.
 * If a color name is assigned an empty or incorrect value (i.e. something
 * containing characters other than decimals and ';'), fields using this color
 * will not be highlighted.
 * If a color is assigned more than once, the last (rightmost) value appearing
 * in the string is kept.
 * Unknown color names are ignored so as to ensure forward compatibility.
 * (Feeling adventurous? Try combining markers: "ac=1;3;5;7;38;2;30;150;100".)
 */
static void
colors_parse_from_env(const struct color_key color_dic[])
{
    const char *color_str = getenv("OVS_COLORS");
    if (color_str == NULL || *color_str == '\0') {
        return;
    }

    /* Loop on tokens: they are separated by columns ':' */
    char *s = xstrdup(color_str);
    char *s_head = s;
    for (char *token = strsep(&s, ":");
         token != NULL;
         token = strsep(&s, ":")) {
        char *name = strsep(&token, "=");
        for (char *ptr = token; ptr != NULL && *ptr != '\0'; ptr++) {
            /* We accept only decimals and ';' for color marker. */
            if (*ptr == ';' || (*ptr >= '0' && *ptr <= '9')) {
                continue;
            }
            name = NULL;
            break;
        }
        if (name != NULL) {
            /* We found a name and marker contains only decimals and ';'.
             * Try to get a pointer to associated color variable. */
            char **color_var_ptr = get_color(color_dic, name);
            /* If we know that color, update its value. */
            if (color_var_ptr != NULL) {
                *color_var_ptr = xasprintf("\33[%sm\33[K", token);
            }
        }
    }
    free(s_head);
}
