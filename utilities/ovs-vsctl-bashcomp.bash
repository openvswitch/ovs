SAVE_IFS=$IFS
IFS="
"
_OVSDB_SERVER_LOCATION=""

# Run ovs-vsctl and make sure that ovs-vsctl is always called with
# the correct --db argument.
_ovs_vsctl () {
    local _db

    if [ -n "$_OVSDB_SERVER_LOCATION" ]; then
        _db="--db=$_OVSDB_SERVER_LOCATION"
    fi
    ovs-vsctl ${_db} "$@"
}

# ovs-vsctl --commands outputs in this format:
#
# main = <localopts>,<name>,<options>
# localopts = ([<localopt>] )*
# localopt = --[^]]*
# name = [^,]*
# arguments = ((!argument|?argument|*argument|+argument) )*
# argument = ([^ ]*|argument\|argument)
#
# The [] characters in local options are just delimiters.  The
# argument prefixes mean:
#   !argument :: The argument is required
#   ?argument :: The argument is optional
#   *argument :: The argument may appear any number (0 or more) times
#   +argument :: The argument may appear one or more times
# A bar (|) character in an argument means thing before bar OR thing
# after bar; for example, del-port can take a port or an interface.

_OVS_VSCTL_COMMANDS="$(_ovs_vsctl --commands)"

# This doesn't complete on short arguments, so it filters them out.
_OVS_VSCTL_OPTIONS="$(_ovs_vsctl --options | awk '/^--/ { print $0 }' \
                      | sed -e 's/\(.*\)=ARG/\1=/')"
IFS=$SAVE_IFS

declare -A _OVS_VSCTL_PARSED_ARGS
declare -A _OVS_VSCTL_NEW_RECORDS

# This is a convenience function to make sure that user input is
# looked at as a fixed string when being compared to something.  $1 is
# the input; this behaves like 'grep "^$1"' but deals with regex
# metacharacters in $1.
_ovs_vsctl_check_startswith_string () {
    awk 'index($0, thearg)==1' thearg="$1"
}

# $1 = word to complete on.
# Complete on global options.
_ovs_vsctl_bashcomp_globalopt () {
    local options result

    options=""
    result=$(printf "%s\n" "${_OVS_VSCTL_OPTIONS}" \
             | _ovs_vsctl_check_startswith_string "${1%=*}")
    if [[ $result =~ "=" ]]; then
        options="NOSPACE"
    fi
    printf -- "${options}\nEO\n${result}"
}

# $1 = word to complete on.
# Complete on local options.
_ovs_vsctl_bashcomp_localopt () {
    local options result possible_opts

    possible_opts=$(printf "%s\n" "${_OVS_VSCTL_COMMANDS}" | cut -f1 -d',')
    # This finds all options that could go together with the
    # already-seen ones
    for prefix_arg in $1; do
        possible_opts=$(printf "%s\n" "$possible_opts" \
                        | grep -- "\[${prefix_arg%%=*}=\?\]")
    done
    result=$(printf "%s\n" "${possible_opts}" \
             | tr ' ' '\n' | tr -s '\n' | sort | uniq)
    # This removes the already-seen options from the list so that
    # users aren't completed for the same option twice.
    for prefix_arg in $1; do
        result=$(printf "%s\n" "${result}" \
                 | grep -v -- "\[${prefix_arg%%=*}=\?\]")
    done
    result=$(printf "%s\n" "${result}" | sed -ne 's/\[\(.*\)\]/\1/p' \
             | _ovs_vsctl_check_startswith_string "$2")
    if [[ $result =~ "=" ]]; then
        options="NOSPACE"
    fi
    printf -- "${options}\nEO\n${result}"
}

# $1 = given local options.
# $2 = word to complete on.
# Complete on command that could contain the given local options.
_ovs_vsctl_bashcomp_command () {
    local result possible_cmds

    possible_cmds=$(printf "%s\n" "${_OVS_VSCTL_COMMANDS}")
    for prefix_arg in $1; do
        possible_cmds=$(printf "%s\n" "$possible_cmds" \
                        | grep -- "\[$prefix_arg=\?\]")
    done
    result=$(printf "%s\n" "${possible_cmds}" \
             | cut -f2 -d',' \
             | _ovs_vsctl_check_startswith_string "$2")
    printf -- "${result}"
}

# $1 = completion result to check.
# Return 0 if the completion result is non-empty, otherwise return 1.
_ovs_vsctl_detect_nonzero_completions () {
    local tmp newarg

    newarg=${1#*EO}
    readarray tmp <<< "$newarg"
    if [ "${#tmp[@]}" -eq 1 ] && [ "${#newarg}" -eq 0 ]; then
        return 1
    fi
    return 0
}

# $1 = argument format to expand.
# Expand '+ARGUMENT' in argument format to '!ARGUMENT *ARGUMENT'.
_ovs_vsctl_expand_command () {
    result=$(printf "%s\n" "${_OVS_VSCTL_COMMANDS}" \
             | grep -- ",$1," | cut -f3 -d',' | tr ' ' '\n' \
             | awk '/\+.*/ { name=substr($0,2);
                             print "!"name; print "*"name; next; }
                    1')
    printf -- "${result}\n!--"
}

# $1 = word to complete on.
# Complete on table.
_ovs_vsctl_complete_table () {
    local result

    result=$(ovsdb-client --no-heading list-tables $_OVSDB_SERVER_LOCATION Open_vSwitch \
        | _ovs_vsctl_check_startswith_string "$1")
    printf -- "EO\n%s\n" "${result}"
}

# $1 = word to complete on.
# Complete on record.  Provide both the name and uuid.
_ovs_vsctl_complete_record () {
    local table uuids names new_record

    table="${_OVS_VSCTL_PARSED_ARGS[TABLE]}"
    new_record="${_OVS_VSCTL_NEW_RECORDS[${table^^}]}"
    # Tables should always have an _uuid column
    uuids=$(_ovs_vsctl --no-heading -f table -d bare --columns=_uuid \
                      list $table | _ovs_vsctl_check_startswith_string "$1")
    # Names don't always exist, silently ignore if the name column is
    # unavailable.
    names=$(_ovs_vsctl --no-heading -f table -d bare \
                      --columns=name list $table \
                      2>/dev/null \
            | _ovs_vsctl_check_startswith_string "$1")
    printf -- "EO\n%s\n%s\n%s\n" "${uuids}" "${names}" "${new_record}"
}

# $1 = word to complete on.
# Complete on bridge.
_ovs_vsctl_complete_bridge () {
    local result

    result=$(_ovs_vsctl list-br | _ovs_vsctl_check_startswith_string "$1")
    printf -- "EO\n%s\n" "${result}"
}

# $1 = word to complete on.
# Complete on port.  If a bridge has already been specified,
# just complete for that bridge.
_ovs_vsctl_complete_port () {
    local ports result

    if [ -n "${_OVS_VSCTL_PARSED_ARGS[BRIDGE]}" ]; then
        ports=$(_ovs_vsctl list-ports "${_OVS_VSCTL_PARSED_ARGS[BRIDGE]}")
    else
        local all_ports
        all_ports=$(_ovs_vsctl --format=table \
                              --no-headings \
                              --columns=name \
                              list Port)
        ports=$(printf "$all_ports" | tr -d '" ' | sort -u)
    fi
    result=$(_ovs_vsctl_check_startswith_string "$1" <<< "$ports")
    printf -- "EO\n%s\n" "${result}"
}

# $1:  Atom to complete (as usual)
# $2:  Table to complete the key in
# $3:  Column to find keys in
# $4:  Prefix for each completion
# Complete on key based on given table and column info.
_ovs_vsctl_complete_key_given_table_column () {
    local keys

    keys=$(_ovs_vsctl --no-heading --columns="$3" list \
                     "$2" \
           | tr -d '{\"}' | tr -s ', ' '\n' | cut -d'=' -f1 \
           | xargs printf "$4%s\n" | _ovs_vsctl_check_startswith_string "$4$1")
    result="${keys}"
    printf -- "%s\n" "${result}"
}

# $1 = word to complete on.
# Complete on key.
__complete_key () {
    # KEY is used in both br-set-external-id/br-get-external id (in
    # which case it is implicitly a key in the external-id column) and
    # in remove, where it is a table key.  This checks to see if table
    # is set (the remove scenario), and then decides what to do.
    local result

    if [ -n "${_OVS_VSCTL_PARSED_ARGS[TABLE]}" ]; then
        local column=$(tr -d '\n' <<< ${_OVS_VSCTL_PARSED_ARGS["COLUMN"]})
        result=$(_ovs_vsctl_complete_key_given_table_column \
                     "$1" \
                     ${_OVS_VSCTL_PARSED_ARGS["TABLE"]} \
                     $column \
                     "")
    else
        result=$(_ovs_vsctl br-get-external-id \
                           ${_OVS_VSCTL_PARSED_ARGS["BRIDGE"]} \
                 | cut -d'=' -f1 | _ovs_vsctl_check_startswith_string "$1")
    fi
    printf -- "%s" "${result}"
}

# $1 = word to complete on.
# Complete on key.
_ovs_vsctl_complete_key () {
    # KEY is used in both br-set-external-id/br-get-external id (in
    # which case it is implicitly a key in the external-id column) and
    # in remove, where it is a table key.  This checks to see if table
    # is set (the remove scenario), and then decides what to do.
    local result

    result="$(__complete_key $1)"
    # If result is empty, just use user input as result.
    if [ -z "$result" ]; then
        result=$1
    fi
    printf -- "EO\n%s\n" "${result}"
}

# $1 = word to complete on.
# Complete on value.
_ovs_vsctl_complete_value () {
    local result

    # Just use user input as result.
    result=$1

    printf -- "EO\n%s\n" "${result}"
}

# $1 = word to complete on.
# Complete on key=value.
_ovs_vsctl_complete_key_value () {
    local orig_completions new_completions

    orig_completions=$(__complete_key "$1")
    for completion in ${orig_completions#*EO}; do
        new_completions="${new_completions} ${completion}="
    done
    # If 'new_completions' is empty, just use user input as result.
    if [ -z "$new_completions" ]; then
        new_completions=$1
    fi
    printf -- "NOSPACE\nEO\n%s" "${new_completions}"
}

# $1 = word to complete on.
# Complete on column.
_ovs_vsctl_complete_column () {
    local columns result

    columns=$(ovsdb-client --no-headings list-columns $_OVSDB_SERVER_LOCATION \
        Open_vSwitch ${_OVS_VSCTL_PARSED_ARGS["TABLE"]})
    result=$(printf "%s\n" "${columns}" \
             | tr -d ':' | cut -d' ' -f1 \
             | _ovs_vsctl_check_startswith_string "$1" | sort | uniq)
    printf -- "EO\n%s\n" "${result}"
}

# Extract all system interfaces.
_ovs_vsctl_get_sys_intf () {
    local result

    case "$(uname -o)" in
        *Linux*)
            result=$(ip -o link 2>/dev/null | cut -d':' -f2 \
                     | sed -e 's/^ \(.*\)/\1/')
            ;;
        *)
            result=$(ifconfig -a -s 2>/dev/null | cut -f1 -d' ' | tail -n +2)
            ;;
    esac
    printf "%s\n" "${result}"
}

# $1 = word to complete on.
# Complete on system interface.
_ovs_vsctl_complete_sysiface () {
    local result

    result=$(_ovs_vsctl_get_sys_intf | _ovs_vsctl_check_startswith_string "$1")
    printf -- "EO\n%s\n" "${result}"
}

# $1 = word to complete on.
# Complete on interface.  If a bridge has already been specified,
# just complete for that bridge.
_ovs_vsctl_complete_iface () {
    local result

    if [ -n "${_OVS_VSCTL_PARSED_ARGS[BRIDGE]}" ]; then
        result=$(_ovs_vsctl list-ifaces "${_OVS_VSCTL_PARSED_ARGS[BRIDGE]}")
    else
        for bridge in $(_ovs_vsctl list-br); do
            local ifaces

            ifaces=$(_ovs_vsctl list-ifaces "${bridge}")
            result="${result} ${ifaces}"
        done
    fi
    printf "EO\n%s\n" "${result}"
}

# $1 = word to complete on.
# Complete on COLUMN?:KEY=VALUE.
_ovs_vsctl_complete_column_optkey_value () {
    local result column key value completion

    column=$(printf "%s\n" "$1" | cut -d '=' -f1 | cut -d':' -f1)
    key=$(printf "%s\n" "$1" | cut -d '=' -f1 | cut -s -d':' -f2)
    # The tr -d '\n' <<< makes sure that there are no leading or
    # trailing accidental newlines.
    table=$(tr -d '\n' <<< ${_OVS_VSCTL_PARSED_ARGS["TABLE"]})
    # This might also be called after add-port or add-bond; in those
    # cases, the table should implicitly be assumed to be "Port".
    # This is done by checking if a NEW- parameter has been
    # encountered and, if it has, using that type without the NEW- as
    # the table.
    if [ -z "$table" ]; then
        if [ -n ${_OVS_VSCTL_PARSED_ARGS["NEW-PORT"]} ] \
           || [ -n ${_OVS_VSCTL_PARSED_ARGS["NEW-BOND-PORT"]} ]; then
            table="Port"
        fi
    fi
    if [ -z "$key" ]; then
        local columns=$(ovsdb-client --no-headings list-columns \
            $_OVSDB_SERVER_LOCATION Open_vSwitch $table)

        result=$(printf "%s\n" "${columns}" \
                 | awk '/key.*value/ { print $1":"; next }
                                     { print $1; next }' \
                 | _ovs_vsctl_check_startswith_string "$1" | sort | uniq)
    fi
    if [[ $1 =~ ":" ]]; then
        result=$(_ovs_vsctl_complete_key_given_table_column \
                     "$key" "$table" "$column" "$column:")
    fi
    # If result is empty, just use user input as result.
    if [ -z "$result" ]; then
        result=$1
    fi
    printf -- "NOSPACE\nEO\n%s\n" "${result}"
}

# $1 = word to complete on.
# Complete on filename.
_ovs_vsctl_complete_filename () {
    local result

    result=$(compgen -o filenames -A file "$1")
    printf -- "EO\n%s\n" "${result}"
}

_ovs_vsctl_complete_bridge_fail_mode () {
    printf -- "EO\nstandalone\nsecure"
}

# $1 = word to complete on.
# Complete on target.
_ovs_vsctl_complete_target () {
    local result

    if [[ "$1" =~ ^p?u ]]; then
        local protocol pathname expansion_base result

        protocol=$(cut -d':' -f1 <<< "$1")
        pathname=$(cut -s -d':' -f2 <<< "$1")
        expansion_base=$(compgen -W "unix punix" "$protocol")
        expansion_base="$expansion_base:"
        result=$(compgen -o filenames -A file \
                         -P $expansion_base "${pathname}")
        printf -- "NOSPACE\nEO\n%s\n" "${result}"
    else
        printf -- "NOSPACE\nEO\nssl:\ntcp:\nunix:\npssl:\nptcp:\npunix:"
    fi
}

# Extract PS1 prompt.
_ovs_vsctl_get_PS1 () {
    if [ "$test" = "true" ]; then
        printf -- "> "
        return;
    fi

    # Original inspiration from
    # http://stackoverflow.com/questions/10060500/bash-how-to-evaluate-ps1-ps2,
    # but changed quite a lot to make it more robust.

    # Make sure the PS1 used doesn't include any of the special
    # strings used to identify the prompt
    myPS1="$(sed 's/Begin prompt/\\Begin prompt/; s/End prompt/\\End prompt/' <<< "$PS1")"
    # Export the current environment in case the prompt uses any
    vars="$(env | cut -d'=' -f1)"
    for var in $vars; do export $var; done
    funcs="$(declare -F | cut -d' ' -f3)"
    for func in $funcs; do export -f $func; done
    # Get the prompt
    v="$(bash --norc --noprofile -i 2>&1 <<< $'PS1=\"'"$myPS1"$'\" \n# Begin prompt\n# End prompt')"
    v="${v##*# Begin prompt}"
    printf -- "$(tail -n +2 <<< "${v%# End prompt*}" | sed 's/\\Begin prompt/Begin prompt/; s/\\End prompt/End prompt/')"

}

# Request a new value from user.  Nothing to complete on.
_ovs_vsctl_complete_new () {
    local two_word_type message result

    if [ ! "$1" = "--" ]; then
        two_word_type="${2/-/ }"
        message="\nEnter a ${two_word_type,,}:\n$(_ovs_vsctl_get_PS1)$COMP_LINE"
        if [ -n "$1" ]; then
            result="$1"
        fi
        printf -- "NOCOMP\nBM%sEM\nEO\n%s\n" "${message}" "${result}"
    fi
}

_ovs_vsctl_complete_dashdash () {
    printf -- "EO\n%s\n" "--"
}


# These functions are given two arguments:
#
# $1 is the word being completed
#
# $2 is the type of completion --- only currently useful for the
# NEW-* functions.
#
# Note that the NEW-* functions actually are ``completed''; currently
# the completions are just used to save the fact that they have
# appeared for later use (i.e. implicit table calculation).
#
# The output is of the form <options>EO<completions>, where EO stands
# for end options.  Currently available options are:
#  - NOSPACE: Do not add a space at the end of each completion
#  - NOCOMP: Do not complete, but store the output of the completion
#    func in _OVS_VSCTL_PARSED_ARGS for later usage.
#  - BM<message>EM: Print the <message>
declare -A _OVS_VSCTL_ARG_COMPLETION_FUNCS=(
    ["TABLE"]=_ovs_vsctl_complete_table
    ["RECORD"]=_ovs_vsctl_complete_record
    ["BRIDGE"]=_ovs_vsctl_complete_bridge
    ["PARENT"]=_ovs_vsctl_complete_bridge
    ["PORT"]=_ovs_vsctl_complete_port
    ["KEY"]=_ovs_vsctl_complete_key
    ["VALUE"]=_ovs_vsctl_complete_value
    ["ARG"]=_ovs_vsctl_complete_value
    ["IFACE"]=_ovs_vsctl_complete_iface
    ["SYSIFACE"]=_ovs_vsctl_complete_sysiface
    ["COLUMN"]=_ovs_vsctl_complete_column
    ["COLUMN?:KEY"]=_ovs_vsctl_complete_column_optkey_value
    ["COLUMN?:KEY=VALUE"]=_ovs_vsctl_complete_column_optkey_value
    ["KEY=VALUE"]=_ovs_vsctl_complete_key_value
    ["?KEY=VALUE"]=_ovs_vsctl_complete_key_value
    ["PRIVATE-KEY"]=_ovs_vsctl_complete_filename
    ["CERTIFICATE"]=_ovs_vsctl_complete_filename
    ["CA-CERT"]=_ovs_vsctl_complete_filename
    ["MODE"]=_ovs_vsctl_complete_bridge_fail_mode
    ["TARGET"]=_ovs_vsctl_complete_target
    ["NEW-BRIDGE"]=_ovs_vsctl_complete_new
    ["NEW-PORT"]=_ovs_vsctl_complete_new
    ["NEW-BOND-PORT"]=_ovs_vsctl_complete_new
    ["NEW-VLAN"]=_ovs_vsctl_complete_new
    ["--"]=_ovs_vsctl_complete_dashdash
)

# $1: Argument type, may include vertical bars to mean OR
# $2: Beginning of completion
#
# Note that this checks for existance in
# _OVS_VSCTL_ARG_COMPLETION_FUNCS; if the argument type ($1) is not
# there it will fail gracefully.
_ovs_vsctl_possible_completions_of_argument () {
    local possible_types completions tmp

    completions="EO"

    possible_types=$(printf "%s\n" "$1" | tr '|' '\n')
    for type in $possible_types; do
        if [ ${_OVS_VSCTL_ARG_COMPLETION_FUNCS["${type^^}"]} ]; then
            tmp=$(${_OVS_VSCTL_ARG_COMPLETION_FUNCS["${type^^}"]} \
                      "$2" "${type^^}")
            tmp_noEO="${tmp#*EO}"
            tmp_EO="${tmp%%EO*}"
            completions=$(printf "%s%s\n%s" "${tmp_EO}" \
                                 "${completions}" "${tmp_noEO}")
        fi
    done
    printf "%s\n" "${completions}"
}

# $1 = List of argument types
# $2 = current pointer into said list
# $3 = word to complete on
# Outputs list of possible completions
# The return value is the index in the cmd_args($1) list that should
# next be matched, if only one of them did, or 254 if there are no
# matches, so it doesn't know what comes next.
_ovs_vsctl_complete_argument() {
    local cmd_args arg expansion index

    new=$(printf "%s\n" "$1" | grep -- '.\+')
    readarray -t cmd_args <<< "$new";
    arg=${cmd_args[$2]}
    case ${arg:0:1} in
        !)
            expansion=$(_ovs_vsctl_possible_completions_of_argument \
                            "${arg:1}" $3)
            index=$(($2+1))
            ;;
        \?|\*)
            local tmp1 tmp2 arg2_index tmp2_noEO tmp2_EO
            tmp1=$(_ovs_vsctl_possible_completions_of_argument "${arg:1}" $3)
            tmp2=$(_ovs_vsctl_complete_argument "$1" "$(($2+1))" "$3")
            arg2_index=$?
            if _ovs_vsctl_detect_nonzero_completions "$tmp1" \
               && _ovs_vsctl_detect_nonzero_completions "$tmp2"; then
                if [ "${arg:0:1}" = "*" ]; then
                    index=$2;
                else
                    index=$(($2+1));
                fi
            fi
            if _ovs_vsctl_detect_nonzero_completions "$tmp1" \
               && (! _ovs_vsctl_detect_nonzero_completions "$tmp2"); then
                if [ "${arg:0:1}" = "*" ]; then
                    index=$2;
                else
                    index=$(($2+1));
                fi
            fi
            if (! _ovs_vsctl_detect_nonzero_completions "$tmp1") \
               && _ovs_vsctl_detect_nonzero_completions "$tmp2"; then
                index=$arg2_index
            fi
            if (! _ovs_vsctl_detect_nonzero_completions "$tmp1") \
               && (! _ovs_vsctl_detect_nonzero_completions "$tmp2"); then
                index=254
            fi
            # Don't allow secondary completions to inhibit primary
            # completions:
            if [[ $tmp2 =~ ^([^E]|E[^O])*NOCOMP ]]; then
                tmp2=""
            fi
            tmp2_noEO="${tmp2#*EO}"
            tmp2_EO="${tmp2%%EO*}"
            expansion=$(printf "%s%s\n%s" "${tmp2_EO}" \
                               "${tmp1}" "${tmp2_noEO}")
            ;;
    esac
    printf "%s\n" "$expansion"
    return $index
}

_ovs_vsctl_detect_nospace () {
    if [[ $1 =~ ^([^E]|E[^O])*NOSPACE ]]; then
        _OVS_VSCTL_COMP_NOSPACE=true
    fi
}

_ovs_vsctl_process_messages () {
    local message

    message="${1#*BM}"
    message="${message%%EM*}"
    if [ "$test" = "true" ]; then
        printf -- "--- BEGIN MESSAGE"
    fi
    printf "${message}"
    if [ "$test" = "true" ]; then
        printf -- "--- END MESSAGE"
    fi
}

# colon, equal sign will mess up the completion output, just
# removes the colon-word and equal-word prefix from COMPREPLY items.
#
# Implementation of this function refers to the __ltrim_colon_completions
# function defined in bash_completion module.
#
# $1:  Current argument
# $2:  $COMP_WORDBREAKS
# $3:  ${COMPREPLY[@]}
_ovs_vsctl_trim_compreply() {
    local cur comp_wordbreaks
    local compreply

    cur=$1 && shift
    comp_wordbreaks=$1 && shift
    compreply=( $@ )

    if [[ "$cur" == *:* && "$comp_wordbreaks" == *:* ]]; then
        local colon_word=${cur%${cur##*:}}
        local i=${#compreply[*]}
        cur=${cur##*:}
        while [ $((--i)) -ge 0 ]; do
            compreply[$i]=${compreply[$i]#"$colon_word"}
        done
    fi

    if [[ "$cur" == *=* && "$comp_wordbreaks" == *=* ]]; then
        local equal_word=${cur%${cur##*=}}
        local i=${#compreply[*]}
        while [ $((--i)) -ge 0 ]; do
            compreply[$i]=${compreply[$i]#"$equal_word"}
        done
    fi

    printf "%s " "${compreply[@]}"
}

# The general strategy here is that the same functions that decide
# completions can also capture the necessary context for later
# completions.  This means that there is no distinction between the
# processing for words that are not the current word and words that
# are the current word.
#
# Parsing up until the command word happens starts with everything
# valid; as the syntax order of ovs-vsctl is fairly strict, when types
# of words that preclude other words from happending can turn them
# off; this is controlled by valid_globals, valid_opts, and
# valid_commands.  given_opts is used to narrow down which commands
# are valid based on the previously given options.
#
# After the command has been detected, the parsing becomes more
# complicated.  The cmd_pos variable is set to 0 when the command is
# detected; it is used as a pointer into an array of the argument
# types for that given command.  The argument types are stored in both
# cmd_args and raw_cmd as the main loop uses properties of arrays to
# detect certain conditions, but arrays cannot be passed to functions.
# To be able to deal with optional or repeatable arguments, the exit
# status of the function _ovs_vsctl_complete_argument represents where
# it has determined that the next argument will be.
_ovs_vsctl_bashcomp () {
    local words cword valid_globals cmd_args raw_cmd cmd_pos valid_globals valid_opts
    local test="false"

    # Does not support BASH_VERSION < 4.0
    if [ ${BASH_VERSINFO[0]} -lt 4 ]; then
        return 0
    fi

    # Prepare the COMP_* variables based on input.
    if [ "$1" = "test" ]; then
        test="true"
        export COMP_LINE="ovs-vsctl $2"
        tmp="ovs-vsctl"$'\n'"$(tr ' ' '\n' <<< "${COMP_LINE}x")"
        tmp="${tmp%x}"
        readarray -t COMP_WORDS \
                  <<< "$tmp"
        export COMP_WORDS
        export COMP_CWORD="$((${#COMP_WORDS[@]}-1))"
    else
        # If not in test mode, reassembles the COMP_WORDS and COMP_CWORD
        # using just space as word break.
        _get_comp_words_by_ref -n "\"'><=;|&(:" -w words -i cword
        COMP_WORDS=( "${words[@]}" )
        COMP_CWORD=${cword}
    fi

    # Extract the conf.db path.
    db=$(sed -n 's/.*--db=\([^ ]*\).*/\1/p' <<< "$COMP_LINE")
    if [ -n "$db" ]; then
        _OVSDB_SERVER_LOCATION="$db"
    fi

    # If having trouble accessing the database, return.
    if ! _ovs_vsctl get-manager 1>/dev/null 2>/dev/null; then
        return 1;
    fi

    _OVS_VSCTL_PARSED_ARGS=()
    _OVS_VSCTL_NEW_RECORDS=()
    cmd_pos=-1
    valid_globals=true
    valid_opts=true
    valid_commands=true
    given_opts=""
    index=1
    for word in "${COMP_WORDS[@]:1:${COMP_CWORD}} "; do
        _OVS_VSCTL_COMP_NOSPACE=false
        local completion
        completion=""
        if [ $cmd_pos -gt -1 ]; then
            local tmp tmp_noop arg possible_newindex
            tmp=$(_ovs_vsctl_complete_argument "$raw_cmd" "$cmd_pos" "$word")
            possible_newindex=$?
            # Check for nospace.
            _ovs_vsctl_detect_nospace $tmp
            # Remove all options.
            tmp_noop="${tmp#*EO}"

            # Allow commands to specify that they should not be
            # completed
            if ! [[ $tmp =~ ^([^E]|E[^O])*NOCOMP ]]; then
                # Directly assignment, since 'completion' is guaranteed to
                # to be empty.
                completion="$tmp_noop"
                # If intermediate completion is empty, it means that the current
                # argument is invalid.  And we should not continue.
                if [ $index -lt $COMP_CWORD ] \
                    && (! _ovs_vsctl_detect_nonzero_completions "$completion"); then
                    _ovs_vsctl_process_messages "BM\nCannot complete \'${COMP_WORDS[$index]}\' at index ${index}:\n$(_ovs_vsctl_get_PS1)${COMP_LINE}EM\nEO\n"
                    return 1
                fi
            else
                # Only allow messages when there is no completion
                # printout and when on the current word.
                if [ $index -eq $COMP_CWORD ]; then
                    _ovs_vsctl_process_messages "${tmp}"
                fi
                # Append the new record to _OVS_VSCTL_NEW_RECORDS.
                _OVS_VSCTL_NEW_RECORDS["${cmd_args[$cmd_pos]##*-}"]="${_OVS_VSCTL_NEW_RECORDS["${cmd_args[$cmd_pos]##*-}"]} $tmp_noop"
            fi
            if [[ $cmd_pos -lt ${#cmd_args} ]]; then
                _OVS_VSCTL_PARSED_ARGS["${cmd_args[$cmd_pos]:1}"]=$word
            fi
            if [ $possible_newindex -lt 254 ]; then
                cmd_pos=$possible_newindex
            fi
        fi

        if [ $valid_globals == true ]; then
            tmp=$(_ovs_vsctl_bashcomp_globalopt $word)
            _ovs_vsctl_detect_nospace $tmp
            completion="${completion} ${tmp#*EO}"
        fi
        if [ $valid_opts == true ]; then
            tmp=$(_ovs_vsctl_bashcomp_localopt "$given_opts" $word)
            _ovs_vsctl_detect_nospace $tmp
            completion="${completion} ${tmp#*EO}"
            if [ $index -lt $COMP_CWORD ] \
               && _ovs_vsctl_detect_nonzero_completions "$tmp"; then
                valid_globals=false
                given_opts="${given_opts} ${word}"
            fi
        fi
        if [ $valid_commands = true ]; then
            tmp=$(_ovs_vsctl_bashcomp_command "$given_opts" $word)
            _ovs_vsctl_detect_nospace $tmp
            completion="${completion} ${tmp#*EO}"
            if [ $index -lt $COMP_CWORD ] \
               && _ovs_vsctl_detect_nonzero_completions "$tmp"; then
                valid_globals=false
                valid_opts=false
                valid_commands=false
                cmd_pos=0
                raw_cmd=$(_ovs_vsctl_expand_command "$word")
                readarray -t cmd_args <<< "$raw_cmd"
            fi
        fi
        if [ "$word" = "--" ] && [ $index -lt $COMP_CWORD ]; then
            # Empty the parsed args array.
            _OVS_VSCTL_PARSED_AGS=()
            cmd_pos=-1
            # No longer allow global options after '--'.
            valid_globals=false
            valid_opts=true
            valid_commands=true
            given_opts=""
        fi
        completion="$(sort -u <<< "$(tr ' ' '\n' <<< ${completion})")"
        if [ $index -eq $COMP_CWORD ]; then
            if [ "$test" = "true" ]; then
                completion="$(_ovs_vsctl_trim_compreply "$word" ":=" ${completion} | \
                              tr ' ' '\n')"
                if [ "${_OVS_VSCTL_COMP_NOSPACE}" = "true" ]; then
                    printf "%s" "$completion" | sed -e '/^$/d'
                else
                    printf "%s" "$completion" | sed -e '/^$/d; s/$/ /g'
                fi
                printf "\n"
            else
                if [ "${_OVS_VSCTL_COMP_NOSPACE}" = "true" ]; then
                    compopt -o nospace
                    COMPREPLY=( $(compgen -W "${completion}" -- $word) )
                else
                    compopt +o nospace
                    COMPREPLY=( $(compgen -W "${completion}" -- $word) )
                fi
                COMPREPLY=( $(_ovs_vsctl_trim_compreply "$word" \
                              "${COMP_WORDBREAKS}" ${COMPREPLY[@]}) )
            fi
        fi
        index=$(($index+1))
    done
}

if [ "$1" = "test" ]; then
    _ovs_vsctl_bashcomp "$@"
else
    complete -F _ovs_vsctl_bashcomp ovs-vsctl
fi
