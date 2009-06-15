/* Copyright (c) 2008, 2009 Nicira Networks, Inc.
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

#include <config.h>
#include "terminal.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dynamic-string.h"
#include "ezio.h"
#include "poll-loop.h"
#include "util.h"

#define THIS_MODULE VLM_terminal
#include "vlog.h"

/* UTF-8 decoding. */
static struct utf8_reader *utf8_reader_create(void);
static void utf8_reader_destroy(struct utf8_reader *);
static int utf8_reader_read(struct utf8_reader *, uint8_t c);

/* ANSI escape sequence decoding. */
struct ansi_sequence {
    int n_args;
#define ANSI_MAX_ARGS 16
    int args[ANSI_MAX_ARGS];
    int function;
};

static struct ansi_decoder *ansi_decoder_create(void);
static void ansi_decoder_destroy(struct ansi_decoder *);
static int ansi_decoder_put(struct ansi_decoder *, uint8_t c);
static const struct ansi_sequence *ansi_decoder_get(struct ansi_decoder *);

/* Terminal emulation. */
struct terminal {
    struct ansi_decoder *ansi;
    struct utf8_reader *utf8;
    enum { EZIO, UTF8 } encoding;
};

static void recv_byte(struct terminal *term, struct ezio *ezio, uint8_t c);

struct terminal *
terminal_create(void)
{
    struct terminal *term = xmalloc(sizeof *term);
    term->ansi = ansi_decoder_create();
    term->utf8 = utf8_reader_create();
    term->encoding = UTF8;
    return term;
}

void
terminal_destroy(struct terminal *term)
{
    if (term) {
        utf8_reader_destroy(term->utf8);
        ansi_decoder_destroy(term->ansi);
        free(term);
    }
}

int
terminal_run(struct terminal *term, struct ezio *ezio, int input_fd)
{
    char input[512];
    int n;

    n = read(input_fd, input, sizeof input);
    if (n > 0) {
        int i;

        for (i = 0; i < n; i++) {
            recv_byte(term, ezio, input[i]);
        }
        return 0;
    } else {
        return !n ? EOF : errno == EAGAIN ? 0 : errno;
    }
}

void
terminal_wait(struct terminal *term UNUSED, int input_fd)
{
    poll_fd_wait(input_fd, POLLIN);
}

static void recv_ansi_sequence(const struct ansi_sequence *, struct ezio *);
static void recv_control(uint8_t c, struct ezio *);
static void recv_character(uint8_t byte, struct ezio *);
static int unicode_to_ezio(uint16_t unicode);
static int default_arg(int value, int default_value);
static int range(int value, int min, int max);
static void clear_elements(uint8_t *p, size_t size, int pos, int clear_type);
static void define_icon(struct ezio *e, const int *args);
static void clear_icon(struct ezio *e, int icon_nr);
static void set_cursor(struct ezio *e, int visibility);

static void
recv_byte(struct terminal *term, struct ezio *ezio, uint8_t c)
{
    int retval;

    /* Decode and interpret ANSI escape sequences. */
    retval = ansi_decoder_put(term->ansi, c);
    if (retval <= 0) {
        if (retval < 0) {
            recv_ansi_sequence(ansi_decoder_get(term->ansi), ezio);
            return;
        }
        return;
    }

    /* Encoding selection. */
    if (c == 0x0e) {
        /* Shift Out. */
        term->encoding = EZIO;
        return;
    } else if (c == 0x0f) {
        /* Shift In. */
        term->encoding = UTF8;
        return;
    }

    if (term->encoding == UTF8) {
        int unicode, ezchar;

        /* Convert UTF-8 input to Unicode code point. */
        unicode = utf8_reader_read(term->utf8, c);
        if (unicode < 0) {
            return;
        }

        /* Convert Unicode code point to EZIO encoding. */
        ezchar = unicode_to_ezio(unicode);
        if (ezchar >= 0) {
            if (ezchar & 0xff00) {
                recv_character(ezchar >> 8, ezio);
            }
            recv_character(ezchar, ezio);
        } else if (unicode < 0x100) {
            recv_control(unicode, ezio);
        } else {
            /* Unsupported Unicode code point. */
            return;
        }
    } else {
        if (c >= 0x80 && c < 0x87) {
            c &= 0x07;
        }
        if (c != 0xfe) {
            recv_character(c, ezio);
        }
    }
}

static void
log_ansi_sequence(const struct ansi_sequence *seq, struct ezio *e)
{
    struct sequence {
        int function;
        const char *name;
    };
    static const struct sequence sequences[] = {
        {0x5a, "CBT: Cursor Backward Tabulation"},
        {0x47, "CHA: Cursor Character Absolute"},
        {0x49, "CHT: Cursor Forward Tabulation"},
        {0x45, "CNL: Cursor Next Line"},
        {0x46, "CPL: Cursor Preceding Line"},
        {0x44, "CUB: Cursor Left"},
        {0x42, "CUD: Cursor Down"},
        {0x43, "CUF: Cursor Right"},
        {0x48, "CUP: Cursor Position"},
        {0x41, "CUU: Cursor Up"},
        {0x50, "DCH: Delete Character"},
        {0x4d, "DL: Delete Line"},
        {0x58, "ECH: Erase Character"},
        {0x4a, "ED: Erase in Page"},
        {0x4b, "EL: Erase in Line"},
        {0x40, "ICH: Insert Character"},
        {0x4c, "IL: Insert Line"},
        {0x4500, "NEL: Next Line"},
        {0x4d00, "RI: Reverse Line Feed"},
        {0x6300, "RIS: Reset to Initial State"},
        {0x54, "SD: Scroll Down"},
        {0x240, "SL: Scroll Left"},
        {0x241, "SR: Scroll Right"},
        {0x53, "SU: Scroll Up"},
        {0x70, "DICO: Define Icon"},
        {0x71, "CICO: Clear Icon"},
        {0x72, "Set cursor visibility"},
    };
    const struct sequence *s;
    struct ds ds;
    int i;

    ds_init(&ds);
    for (s = sequences; s < &sequences[ARRAY_SIZE(sequences)]; s++) {
        if (s->function == seq->function) {
            ds_put_cstr(&ds, s->name);
            goto found;
        }
    }
    ds_put_format(&ds, "0x%02x", s->function);
    if (s->function < 0x100) {
        ds_put_format(&ds, "(%02d/%02d)", s->function / 16, s->function % 16);
    }

found:
    for (i = 0; i < seq->n_args; i++) {
        ds_put_format(&ds, ", %d", seq->args[i]);
    }
    VLOG_DBG("%s (cursor:%d,%d)", ds_cstr(&ds), e->x, e->y);
    ds_destroy(&ds);
}

static void
recv_ansi_sequence(const struct ansi_sequence *seq, struct ezio *e)
{
#define ARG1(DEFAULT) default_arg(seq->args[0], DEFAULT)
#define ARG2(DEFAULT) default_arg(seq->args[1], DEFAULT)
    if (VLOG_IS_DBG_ENABLED()) {
        log_ansi_sequence(seq, e);
    }
    switch (seq->function) {
    case 0x5a: /* CBT: Cursor Backward Tabulation. */
        e->x = 8 * (e->x / 8 - ARG1(1));
        break;
    case 0x47: /* CHA: Cursor Character Absolute. */
        e->x = ARG1(1) - 1;
        break;
    case 0x49: /* CHT: Cursor Forward Tabulation. */
        e->x = 8 * (e->x / 8 + ARG1(1));
        break;
    case 0x45: /* CNL: Cursor Next Line. */
        e->x = 0;
        e->y += ARG1(1);
        break;
    case 0x46: /* CPL: Cursor Preceding Line. */
        e->x = 0;
        e->y -= ARG1(1);
        break;
    case 0x44: /* CUB: Cursor Left. */
        e->x -= ARG1(1);
        break;
    case 0x42: /* CUD: Cursor Down. */
        e->y += ARG1(1);
        break;
    case 0x43: /* CUF: Cursor Right. */
        e->x += ARG1(1);
        break;
    case 0x48: /* CUP: Cursor Position. */
        e->y = ARG1(1) - 1;
        e->x = ARG2(1) - 1;
        break;
    case 0x41: /* CUU: Cursor Up. */
        e->y -= ARG1(1);
        break;
    case 0x50: /* DCH: Delete Character. */
        ezio_delete_char(e, e->x, e->y, ARG1(1));
        break;
    case 0x4d: /* DL: Delete Line. */
        ezio_delete_line(e, e->y, ARG1(1));
        break;
    case 0x58: /* ECH: Erase Character. */
        memset(&e->chars[e->y][e->x], ' ', MIN(ARG1(1), 40 - e->x));
        break;
    case 0x4a: /* ED: Erase in Page. */
        clear_elements(&e->chars[0][0], 2 * 40, e->x + 40 * e->y, ARG1(0));
        break;
    case 0x4b: /* EL: Erase in Line. */
        clear_elements(&e->chars[e->y][0], 40, e->x, ARG1(0));
        break;
    case 0x40: /* ICH: Insert Character. */
        ezio_insert_char(e, e->x, e->y, ARG1(1));
        break;
    case 0x4c: /* IL: Insert Line. */
        ezio_insert_line(e, e->y, ARG1(1));
        break;
    case 0x4500: /* NEL: Next Line. */
        e->x = 0;
        e->y++;
        break;
    case 0x4d00: /* RI: Reverse Line Feed. */
        e->y--;
        break;
    case 0x6300: /* RIS: Reset to Initial State. */
        ezio_init(e);
        break;
    case 0x54: /* SD: Scroll Down. */
        ezio_scroll_down(e, ARG1(1));
        break;
    case 0x240: /* SL: Scroll Left. */
        ezio_scroll_left(e, ARG1(1));
        break;
    case 0x241: /* SR: Scroll Right. */
        ezio_scroll_right(e, ARG1(1));
        break;
    case 0x53: /* SU: Scroll Up. */
        ezio_scroll_up(e, ARG1(1));
        break;

        /* Private sequences. */
    case 0x70: /* DICO: Define Icon. */
        define_icon(e, seq->args);
        break;
    case 0x71: /* CICO: Clear Icon. */
        clear_icon(e, ARG1(0));
        break;
    case 0x72: /* Set cursor visibility. */
        set_cursor(e, ARG1(1));
        break;
    }
    e->x = range(e->x, 0, 40);
    e->y = range(e->y, 0, 1);
    VLOG_DBG("cursor:%d,%d", e->x, e->y);
}

static void
recv_control(uint8_t c, struct ezio *e)
{
    switch (c) {
    case '\b':
        if (e->x > 0) {
            --e->x;
        }
        break;

    case '\t':
        e->x = ROUND_UP(e->x + 1, 8);
        if (e->x > 40) {
            ezio_newline(e);
        }
        break;

    case '\n':
        ezio_line_feed(e);
        break;

    case '\f':
        ezio_clear(e);
        break;

    case '\r':
        e->x = 0;
        break;

    default:
        VLOG_DBG("Unhandled control character 0x%02"PRIx8, c);
    }
}

static void
recv_character(uint8_t byte, struct ezio *e)
{
    if (e->x >= 40) {
        ezio_newline(e);
    }
    ezio_put_char(e, e->x++, e->y, byte);
}

static int
default_arg(int value, int default_value)
{
    return value >= 0 ? value : default_value;
}

static int
range(int value, int min, int max)
{
    return value < min ? min : value > max ? max : value;
}

static void
clear_elements(uint8_t *p, size_t size, int pos, int clear_type)
{
    switch (clear_type) {
    case 0:
        /* Clear from 'pos' to end. */
        memset(p + pos, ' ', size - pos);
        break;
    case 1:
        /* Clear from beginning to 'pos'. */
        memset(p, ' ', pos + 1);
        break;
    case 2:
        /* Clear all. */
        memset(p, ' ', size);
        break;
    }
}

static void
define_icon(struct ezio *e, const int *args)
{
    int icon_nr;
    int row;

    icon_nr = args[0];
    if (icon_nr < 0 || icon_nr > 7) {
        return;
    }

    for (row = 0; row < 8; row++) {
        e->icons[icon_nr][row] = default_arg(args[row + 1], 0) & 0x1f;
    }
}

static void
clear_icon(struct ezio *e, int icon_nr)
{
    if (icon_nr >= 0 && icon_nr <= 7) {
        ezio_set_default_icon(e, icon_nr);
    }
}

static void
set_cursor(struct ezio *e, int visibility)
{
    switch (visibility) {
    case 1:
        e->show_cursor = e->blink_cursor = false;
        break;
    case 2:
        e->show_cursor = true;
        e->blink_cursor = false;
        break;
    case 3:
        e->show_cursor = e->blink_cursor = true;
        break;
    }
}

static int
unicode_to_ezio(uint16_t unicode)
{
    switch (unicode) {
        /* Most ASCII characters map one-to-one. */
    case 0x0020 ... 0x005b:
    case 0x005d ... 0x007d:
        return unicode;

        /* A few ASCII characters have to be simulated with icons. */
    case 0x005c: return 0x06; /* BACKSLASH */
    case 0x007e: return 0x07; /* TILDE */

        /* EZIO extended characters equivalents in Unicode - Japanese. */
    case 0x00a5: return '\\';   /* YEN SIGN */
    case 0x3002: return 0xa1;   /* IDEOGRAPHIC FULL STOP */
    case 0x300c: return 0xa2;   /* LEFT CORNER BRACKET */
    case 0x300d: return 0xa3;   /* RIGHT CORNER BRACKET */
    case 0x3001: return 0xa4;   /* IDEOGRAPHIC COMMA */
    case 0x30fb: return 0xa5;   /* KATAKANA MIDDLE DOT */
    case 0x30f2: return 0xa6;   /* KATAKANA LETTER WO */
    case 0x30a1: return 0xa7;   /* KATAKANA LETTER SMALL A */
    case 0x30a3: return 0xa8;   /* KATAKANA LETTER SMALL I */
    case 0x30a5: return 0xa9;   /* KATAKANA LETTER SMALL U */
    case 0x30a7: return 0xaa;   /* KATAKANA LETTER SMALL E */
    case 0x30a9: return 0xab;   /* KATAKANA LETTER SMALL O */
    case 0x30e3: return 0xac;   /* KATAKANA LETTER SMALL YA */
    case 0x30e5: return 0xad;   /* KATAKANA LETTER SMALL YU */
    case 0x30e7: return 0xae;   /* KATAKANA LETTER SMALL YO */
    case 0x30c3: return 0xaf;   /* KATAKANA LETTER SMALL TU = SMALL TSU */
	case 0x30fc: return 0xb0;   /* KATAKANA-HIRAGANA PROLONGED SOUND MARK */
    case 0x30a2: return 0xb1;   /* KATAKANA LETTER A */
    case 0x30a4: return 0xb2;   /* KATAKANA LETTER I */
    case 0x30a6: return 0xb3;   /* KATAKANA LETTER U */
    case 0x30a8: return 0xb4;   /* KATAKANA LETTER E */
    case 0x30aa: return 0xb5;   /* KATAKANA LETTER O */
    case 0x30ab: return 0xb6;   /* KATAKANA LETTER KA */
    case 0x30ac: return 0xb6de; /* KATAKANA LETTER GA */
    case 0x30ad: return 0xb7;   /* KATAKANA LETTER KI */
    case 0x30ae: return 0xb7de; /* KATAKANA LETTER GI */
    case 0x30af: return 0xb8;   /* KATAKANA LETTER KU */
    case 0x30b0: return 0xb8de; /* KATAKANA LETTER GU */
    case 0x30b1: return 0xb9;   /* KATAKANA LETTER KE */
    case 0x30b2: return 0xb9de; /* KATAKANA LETTER GE */
    case 0x30b3: return 0xba;   /* KATAKANA LETTER KO */
    case 0x30b4: return 0xbade; /* KATAKANA LETTER GO */
    case 0x30b5: return 0xbb;   /* KATAKANA LETTER SA */
    case 0x30b6: return 0xbbde; /* KATAKANA LETTER ZA */
    case 0x30b7: return 0xbc;   /* KATAKANA LETTER SI = SHI */
    case 0x30b8: return 0xbcde; /* KATAKANA LETTER ZI = JI */
    case 0x30b9: return 0xbd;   /* KATAKANA LETTER SU */
    case 0x30ba: return 0xbdde; /* KATAKANA LETTER ZU */
    case 0x30bb: return 0xbe;   /* KATAKANA LETTER SE */
    case 0x30bc: return 0xbede; /* KATAKANA LETTER ZE */
    case 0x30bd: return 0xbf;   /* KATAKANA LETTER SO */
    case 0x30be: return 0xbfde; /* KATAKANA LETTER ZO */
    case 0x30bf: return 0xc0;   /* KATAKANA LETTER TA */
    case 0x30c0: return 0xc0de; /* KATAKANA LETTER DA */
    case 0x30c1: return 0xc1;   /* KATAKANA LETTER TI = CHI */
    case 0x30c2: return 0xc1de; /* KATAKANA LETTER DI = JI */
    case 0x30c4: return 0xc2;   /* KATAKANA LETTER TU = TSU */
    case 0x30c5: return 0xc2de; /* KATAKANA LETTER DU = ZU */
    case 0x30c6: return 0xc3;   /* KATAKANA LETTER TE */
    case 0x30c7: return 0xc3de; /* KATAKANA LETTER DE */
    case 0x30c8: return 0xc4;   /* KATAKANA LETTER TO */
    case 0x30c9: return 0xc4de; /* KATAKANA LETTER DO */
    case 0x30ca: return 0xc5;   /* KATAKANA LETTER NA */
    case 0x30cb: return 0xc6;   /* KATAKANA LETTER NI */
    case 0x30cc: return 0xc7;   /* KATAKANA LETTER NU */
    case 0x30cd: return 0xc8;   /* KATAKANA LETTER NE */
    case 0x30ce: return 0xc9;   /* KATAKANA LETTER NO */
    case 0x30cf: return 0xca;   /* KATAKANA LETTER HA */
    case 0x30d0: return 0xcade; /* KATAKANA LETTER BA */
    case 0x30d1: return 0xcadf; /* KATAKANA LETTER PA */
    case 0x30d2: return 0xcb;   /* KATAKANA LETTER HI */
    case 0x30d3: return 0xcbde; /* KATAKANA LETTER BI */
    case 0x30d4: return 0xcbdf; /* KATAKANA LETTER PI */
    case 0x30d5: return 0xcc;   /* KATAKANA LETTER HU = FU */
    case 0x30d6: return 0xccde; /* KATAKANA LETTER BU */
    case 0x30d7: return 0xccdf; /* KATAKANA LETTER PU */
    case 0x30d8: return 0xcd;   /* KATAKANA LETTER HE */
    case 0x30d9: return 0xcdde; /* KATAKANA LETTER BE */
    case 0x30da: return 0xcddf; /* KATAKANA LETTER PE */
    case 0x30db: return 0xce;   /* KATAKANA LETTER HO */
    case 0x30dc: return 0xcede; /* KATAKANA LETTER BO */
    case 0x30dd: return 0xcedf; /* KATAKANA LETTER PO */
    case 0x30de: return 0xcf;   /* KATAKANA LETTER MA */
    case 0x30df: return 0xd0;   /* KATAKANA LETTER MI */
    case 0x30e0: return 0xd1;   /* KATAKANA LETTER MU */
    case 0x30e1: return 0xd2;   /* KATAKANA LETTER ME */
    case 0x30e2: return 0xd3;   /* KATAKANA LETTER MO */
    case 0x30e4: return 0xd4;   /* KATAKANA LETTER YA */
    case 0x30e6: return 0xd5;   /* KATAKANA LETTER YU */
    case 0x30e8: return 0xd6;   /* KATAKANA LETTER YO */
    case 0x30e9: return 0xd7;   /* KATAKANA LETTER RA */
    case 0x30ea: return 0xd8;   /* KATAKANA LETTER RI */
    case 0x30eb: return 0xd9;   /* KATAKANA LETTER RU */
    case 0x30ec: return 0xda;   /* KATAKANA LETTER RE */
    case 0x30ed: return 0xdb;   /* KATAKANA LETTER RO */
    case 0x30ef: return 0xdc;   /* KATAKANA LETTER WA */
    case 0x30f3: return 0xdd;   /* KATAKANA LETTER N */
    case 0x30f4: return 0xb3de; /* KATAKANA LETTER VU */
    case 0x30f7: return 0xdcde; /* KATAKANA LETTER VA */
    case 0x3099: return 0xde;   /* COMBINING KATAKANA-HIRAGANA VOICED SOUND
                                 * MARK */
    case 0x309a: return 0xdf;   /* COMBINING KATAKANA-HIRAGANA SEMI-VOICED
                                 * SOUND MARK */
    case 0x309b: return 0xde;   /* KATAKANA-HIRAGANA VOICED SOUND MARK */
	case 0x309c: return 0xdf;   /* KATAKANA-HIRAGANA SEMI-VOICED SOUND MARK */

        /* EZIO extended characters equivalents in Unicode - other. */
    case 0x2192: return 0x7e; /* RIGHTWARDS ARROW */
    case 0x2190: return 0x7f; /* LEFTWARDS ARROW */
    case 0x03b1: return 0xe0; /* GREEK SMALL LETTER ALPHA */
    case 0x00e4: return 0xe1; /* LATIN SMALL LETTER A WITH DIAERESIS */
    case 0x03b2: return 0xe2; /* GREEK SMALL LETTER BETA */
    case 0x03b5: return 0xe3; /* GREEK SMALL LETTER EPSILON */
    case 0x03bc: return 0xe4; /* GREEK SMALL LETTER MU */
    case 0x03c6: return 0xe5; /* GREEK SMALL LETTER PHI */
    case 0x03c1: return 0xe6; /* GREEK SMALL LETTER RHO */
                              /* 0xe7 is 'g'. */
    case 0x221a: return 0xe8; /* SQUARE ROOT = radical sign */
                              /* 0xe9 is an unrecognizable symbol. */
                              /* 0xea is 'j'. */
                              /* 0xeb is an unrecognizable symbol.*/
    case 0x00a2: return 0xec; /* CENT SIGN */
    case 0x00a3: return 0xed; /* POUND SIGN */
    case 0x00f1: return 0xee; /* LATIN SMALL LETTER N WITH TILDE */
    case 0x00f6: return 0xef; /* LATIN SMALL LETTER O WITH DIAERESIS */
                              /* 0xf0 is 'p'. */
                              /* 0xf1 is 'q'. */
    case 0x03b8: return 0xf2; /* GREEK SMALL LETTER THETA */
    case 0x221e: return 0xf3; /* INFINITY */
    case 0x03a9: return 0xf4; /* GREEK CAPITAL LETTER OMEGA */
    case 0x00fc: return 0xf5; /* LATIN SMALL LETTER U WITH DIAERESIS */
    case 0x03a3: return 0xf6; /* GREEK CAPITAL LETTER SIGMA */
    case 0x03c0: return 0xf7; /* GREEK SMALL LETTER PI */
                              /* 0xf8 is x-macron (the sample mean). */
                              /* 0xf9 is 'y'. */
    case 0x5343: return 0xfa; /* thousand */
    case 0x4e07: return 0xfb; /* ten thousand */
    case 0x5186: return 0xfc; /* yen */
    case 0x00f7: return 0xfd; /* DIVISION SIGN */
    case 0x2588: return 0xff; /* FULL BLOCK = solid */

        /* EZIO icons (from the Unicode Private Use corporate subarea). */
    case 0xf8f8: return 0x00;
    case 0xf8f9: return 0x01;
    case 0xf8fa: return 0x02;
    case 0xf8fb: return 0x03;
    case 0xf8fc: return 0x04;
    case 0xf8fd: return 0x05;
    case 0xf8fe: return 0x06;
    case 0xf8ff: return 0x07;

        /* No mappings for anything else. */
    default: return -1;
    }
}

/* UTF-8 decoder. */

#define UTF_STATES                              \
    UTF_STATE(UTF8_INIT, 0x00, 0xf4, UTF8_INIT) \
    UTF_STATE(UTF8_3,    0x80, 0xbf, UTF8_2)    \
    UTF_STATE(UTF8_2,    0x80, 0xbf, UTF8_1)    \
    UTF_STATE(UTF8_1,    0x80, 0xbf, UTF8_INIT) \
    UTF_STATE(UTF8_E0,   0xa0, 0xbf, UTF8_1)    \
    UTF_STATE(UTF8_ED,   0x80, 0x9f, UTF8_1)    \
    UTF_STATE(UTF8_F0,   0x90, 0xbf, UTF8_INIT) \
    UTF_STATE(UTF8_F4,   0x80, 0x8f, UTF8_INIT)

enum state {
#define UTF_STATE(NAME, MIN, MAX, NEXT) NAME,
    UTF_STATES
#undef UTF_STATE
};

struct state_info {
    uint8_t min, max;
    enum state next;
};

static const struct state_info states[] = {
#define UTF_STATE(NAME, MIN, MAX, NEXT) {MIN, MAX, NEXT},
    UTF_STATES
#undef UTF_STATE
};

struct utf8_reader {
    int cp;
    enum state state;
};

struct utf8_reader *
utf8_reader_create(void)
{
    struct utf8_reader *r = xmalloc(sizeof *r);
    r->state = UTF8_INIT;
    return r;
}

void
utf8_reader_destroy(struct utf8_reader *r)
{
    free(r);
}

int
utf8_reader_read(struct utf8_reader *r, uint8_t c)
{
    const struct state_info *s = &states[r->state];
    if (c >= s->min && c <= s->max) {
        if (r->state == UTF8_INIT) {
            if (c < 0x80) {
                return c;
            } else if (c >= 0xc2 && c <= 0xdf) {
                r->cp = c & 0x1f;
                r->state = UTF8_1;
                return -1;
            } else if (c >= 0xe0 && c <= 0xef) {
                r->cp = c & 0x0f;
                r->state = c == 0xe0 ? UTF8_E0 : c == 0xed ? UTF8_ED : UTF8_2;
                return -1;
            } else if (c >= 0xf0 && c <= 0xf4) {
                r->cp = c & 0x07;
                r->state = c == 0xf0 ? UTF8_F0 : c == 0xf4 ? UTF8_F4 : UTF8_3;
                return -1;
            }
        } else {
            r->cp = (r->cp << 6) | (c & 0x3f);
            r->state = s->next;
            return r->state == UTF8_INIT ? r->cp : -1;
        }
    }

    /* Invalid UTF-8 sequence.  Return the Unicode general substitute
     * REPLACEMENT CHARACTER. */
    r->state = UTF8_INIT;
    return 0xfffd;
}

/* ANSI control sequence decoder. */

/* States are named for what we are looking for in that state. */
enum ansi_state {
    ANSI_ESC,                      /* Looking for ESC. */
    ANSI_CSI,                      /* Looking for [ (to complete CSI). */
    ANSI_PARAMETER,                /* Looking for parameter. */
    ANSI_INTERMEDIATE,             /* Looking for intermediate byte. */
    ANSI_FINAL,                    /* Looking for final byte. */
    ANSI_COMPLETE                  /* Got an entire escape sequence. */
};

struct ansi_decoder {
    enum ansi_state state;
    struct ansi_sequence seq;
    int c;
};

struct ansi_decoder *
ansi_decoder_create(void)
{
    struct ansi_decoder *d = xmalloc(sizeof *d);
    d->state = ANSI_ESC;
    return d;
}

void
ansi_decoder_destroy(struct ansi_decoder *d)
{
    free(d);
}

int
ansi_decoder_put(struct ansi_decoder *d, uint8_t c)
{
    if (c == 27) {
        /* Escape always starts a new escape sequence, aborting an incomplete
         * one if necessary. */
        if (d->state != ANSI_ESC) {
            VLOG_DBG("Unexpected escape inside escape sequence");
        }
        d->state = ANSI_CSI;
        return 0;
    }

    switch (d->state) {
    case ANSI_ESC:
        return 1;

    case ANSI_CSI:
        if (c == '[') {
            d->state = ANSI_PARAMETER;
            d->seq.n_args = 0;
            d->seq.function = 0;
        } else if (c >= 0x40 && c <= 0x5f) {
            d->state = ANSI_COMPLETE;
            d->seq.n_args = 0;
            d->seq.function = 0;
            d->seq.function = c << 8;
            return -1;
        } else {
            d->state = ANSI_ESC;
        }
        break;

    case ANSI_PARAMETER:
        if (c >= '0' && c <= '9') {
            int *arg;
            if (d->seq.n_args == 0) {
                d->seq.args[d->seq.n_args++] = 0;
            } else if (d->seq.n_args > ANSI_MAX_ARGS) {
                break;
            }
            arg = &d->seq.args[d->seq.n_args - 1];
            if (*arg == -1) {
                *arg = 0;
            }
            *arg = *arg * 10 + (c - '0');
            break;
        } else if (c == ';') {
            if (d->seq.n_args < ANSI_MAX_ARGS) {
                d->seq.args[d->seq.n_args] = -1;
            }
            d->seq.n_args++;
            break;
        }
        d->state = ANSI_INTERMEDIATE;
        /* Fall through. */

    case ANSI_INTERMEDIATE:
        if (c >= 0x20 && c <= 0x2f) {
            d->seq.function = d->seq.function * 16 + (c - 0x20);
            break;
        }
        d->state = ANSI_FINAL;
        /* Fall through. */

    case ANSI_FINAL:
        if (c >= 0x40 && c <= 0x7e) {
            d->seq.function = d->seq.function * 256 + c;
            d->state = ANSI_COMPLETE;
            return -1;
        } else {
            /* Invalid sequence. */
            d->state = ANSI_ESC;
        }
        break;

    case ANSI_COMPLETE:
        NOT_REACHED();
    }
    return 0;
}

const struct ansi_sequence *
ansi_decoder_get(struct ansi_decoder *d)
{
    assert(d->state == ANSI_COMPLETE);
    d->state = ANSI_ESC;
    if (d->seq.n_args < ANSI_MAX_ARGS) {
        int i;
        for (i = d->seq.n_args; i < ANSI_MAX_ARGS; i++) {
            d->seq.args[i] = -1;
        }
    } else {
        d->seq.n_args = ANSI_MAX_ARGS;
    }
    return &d->seq;
}
