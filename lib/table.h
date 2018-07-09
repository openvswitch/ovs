/*
 * Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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

#ifndef TABLE_H
#define TABLE_H 1

#include <stdbool.h>
#include <stddef.h>
#include "compiler.h"

struct ds;
struct table_style;

/* Manipulating tables and their rows and columns. */

struct table {
    struct cell *cells;
    struct column *columns;
    size_t n_columns, allocated_columns;
    size_t n_rows, allocated_rows;
    size_t current_column;
    char *caption;
    bool timestamp;
};

void table_init(struct table *);
void table_destroy(struct table *);
void table_set_caption(struct table *, char *caption);
void table_set_timestamp(struct table *, bool timestamp);

void table_add_column(struct table *, const char *heading, ...)
    OVS_PRINTF_FORMAT(2, 3);
void table_add_row(struct table *);

/* Table cells. */

struct cell {
    /* Literal text. */
    char *text;

    /* JSON. */
    struct json *json;
    const struct ovsdb_type *type;
};

struct cell *table_add_cell(struct table *);

/* Table formatting. */

enum table_format {
    TF_TABLE,                   /* 2-d table. */
    TF_LIST,                    /* One cell per line, one row per paragraph. */
    TF_HTML,                    /* HTML table. */
    TF_CSV,                     /* Comma-separated lines. */
    TF_JSON                     /* JSON. */
};

enum cell_format {
    CF_STRING,                  /* String format. */
    CF_BARE,                    /* String format without most punctuation. */
    CF_JSON                     /* JSON. */
};

struct table_style {
    enum table_format format;   /* TF_*. */
    enum cell_format cell_format; /* CF_*. */
    bool headings;              /* Include headings? */
    int json_flags;             /* CF_JSON: Flags for json_to_string(). */
    int max_column_width;       /* CF_STRING: Limit for column width. */
};

#define TABLE_STYLE_DEFAULT { TF_LIST, CF_STRING, true, JSSF_SORT, 0 }

#define TABLE_OPTION_ENUMS                      \
    OPT_NO_HEADINGS,                            \
    OPT_PRETTY,                                 \
    OPT_BARE,                                   \
    OPT_MAX_COLUMN_WIDTH

#define TABLE_LONG_OPTIONS                                      \
        {"format", required_argument, NULL, 'f'},               \
        {"data", required_argument, NULL, 'd'},                 \
        {"no-headings", no_argument, NULL, OPT_NO_HEADINGS},    \
        {"pretty", no_argument, NULL, OPT_PRETTY},              \
        {"bare", no_argument, NULL, OPT_BARE},                  \
        {"max-column-width", required_argument, NULL, OPT_MAX_COLUMN_WIDTH}

#define TABLE_OPTION_HANDLERS(STYLE)                \
        case 'f':                                   \
            table_parse_format(STYLE, optarg);      \
            break;                                  \
                                                    \
        case 'd':                                   \
            table_parse_cell_format(STYLE, optarg); \
            break;                                  \
                                                    \
        case OPT_NO_HEADINGS:                       \
            (STYLE)->headings = false;              \
            break;                                  \
                                                    \
        case OPT_PRETTY:                            \
            (STYLE)->json_flags |= JSSF_PRETTY;     \
            break;                                  \
                                                    \
        case OPT_BARE:                              \
            (STYLE)->format = TF_LIST;              \
            (STYLE)->cell_format = CF_BARE;         \
            (STYLE)->headings = false;              \
            break;                                  \
                                                    \
        case OPT_MAX_COLUMN_WIDTH:                  \
            (STYLE)->max_column_width = atoi(optarg); \
            break;

void table_parse_format(struct table_style *, const char *format);
void table_parse_cell_format(struct table_style *, const char *format);

void table_print(const struct table *, const struct table_style *);
void table_format(const struct table *, const struct table_style *,
                  struct ds *);
void table_usage(void);

#endif /* table.h */
