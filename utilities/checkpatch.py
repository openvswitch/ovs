#!/usr/bin/env python
spellcheck_comments = False
                          'recirculation']
__regex_if_macros = re.compile(r'^ +(%s) \([\S][\s\S]+[\S]\) { \\' %
def check_comment_spelling(line):
    if not spell_check_dict or not spellcheck_comments:
    comment_words = filter_comments(line, True).replace(':', ' ').split(' ')
    for word in comment_words:
        if len(strword) and not spell_check_dict.check(strword.lower()):
            # skip words that start with numbers
            if strword.startswith(tuple('0123456789')):
     'check': lambda x: check_comment_spelling(x)},
-S|--spellcheck-comments       Check C comments for possible spelling mistakes
                                       "spellcheck-comments",
        elif o in ("-S", "--spellcheck-comments"):
                spellcheck_comments = True