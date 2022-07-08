#
# A bash command completion script for ovs-appctl.
#
#
# Right now, the script can do the following:
#
#    - display available completion or complete on unfinished user input
#      (long option, subcommand, and argument).
#
#    - once the subcommand (e.g. ofproto/trace) has been given, the
#      script will print the subcommand format.
#
#    - the script can convert between keywords like 'bridge/port/interface/dp'
#      and the available record in ovsdb.
#
# The limitation are:
#
#    - only support small set of important keywords
#      (dp, datapath, bridge, switch, port, interface, iface).
#
#    - does not support parsing of nested option
#      (e.g. ovsdb-tool create [db [schema]]).
#
#    - does not support expansion on repeatitive argument
#      (e.g. ovs-dpctl show [dp...]).
#
#    - only support matching on long options, and only in the format
#      (--option [arg], i.e. should not use --option=[arg]).
#
#
#
# Keywords
# ========
#
#
#
# Expandable keywords.
_KWORDS=(bridge switch port interface iface dp_name dp)
# Command name.
_COMMAND=
# Printf enabler.
_PRINTF_ENABLE=
# Bash prompt.
_BASH_PROMPT=
# Output to the compgen.
_COMP_WORDLIST=

#
# For ovs-appctl command only.
#
# Target in the current completion, default ovs-vswitchd.
_APPCTL_TARGET=
# Possible targets.
_POSSIBLE_TARGETS="ovs-vswitchd ovsdb-server ovs-ofctl"

# Command Extraction
# ==================
#
#
#
# Extracts all subcommands of 'command'.
# If fails, returns nothing.
extract_subcmds() {
    local command=$_COMMAND
    local target=
    local subcmds error

    if [ -n "$_APPCTL_TARGET" ]; then
        target="--target $_APPCTL_TARGET"
    fi

    subcmds="$($command $target list-commands 2>/dev/null | tail -n +2 | cut -c3- \
                 | cut -d ' ' -f1)" || error="TRUE"

    if [ -z "$error" ]; then
        echo "$subcmds"
    fi
}

# Extracts all long options of ovs-appctl.
# If fails, returns nothing.
extract_options() {
    local command=$_COMMAND
    local options error

    options="$($command --option 2>/dev/null | sort | sed -n '/^--.*/p' | cut -d '=' -f1)" \
        || error="TRUE"

    if [ -z "$error" ]; then
        echo "$options"
    fi
}

# Returns the option format, if the option asks for an argument.
# If fails, returns nothing.
option_require_arg() {
    local command=$_COMMAND
    local option=$1
    local require_arg error

    require_arg="$($command --option | sort | sed -n '/^--.*/p' | grep -- "$option" | grep -- "=")" \
        || error="TRUE"

    if [ -z "$error" ]; then
        echo "$require_arg"
    fi
}

# Combination Discovery
# =====================
#
#
#
# Given the subcommand formats, finds all possible completions
# at current completion level.
find_possible_comps() {
    local combs="$@"
    local comps=
    local line

    while read line; do
        local arg=

        for arg in $line; do
            # If it is an optional argument, gets all completions,
            # and continues.
            if [ -n "$(sed -n '/^\[.*\]$/p' <<< "$arg")" ]; then
                local opt_arg="$(sed -e 's/^\[\(.*\)\]$/\1/' <<< "$arg")"
                local opt_args=()

                IFS='|' read -a opt_args <<< "$opt_arg"
                comps="${opt_args[@]} $comps"
            # If it is in format "\[*", it is a start of nested
            # option, do not parse.
            elif [ -n "$(sed -n "/^\[.*$/p" <<< "$arg")" ]; then
                break;
            # If it is a compulsory argument, adds it to the comps
            # and break, since all following args are for next stage.
            else
                local args=()

                IFS='|' read -a args <<< "$arg"
                comps="${args[@]} $comps"
                break;
            fi
        done
    done <<< "$combs"

    echo "$comps"
}

# Given the subcommand format, and the current command line input,
# finds keywords of all possible completions.
subcmd_find_keyword_based_on_input() {
    local format="$1"
    local cmd_line=($2)
    local mult=
    local combs=
    local comps=
    local arg line

    # finds all combinations by searching for '{}'.
    # there should only be one '{}', otherwise, the
    # command format should be changed to multiple commands.
    mult="$(sed -n 's/^.*{\(.*\)}.*$/ \1/p' <<< "$format" | tr '|' '\n' | cut -c1-)"
    if [ -n "$mult" ]; then
        while read line; do
            local tmp=

            tmp="$(sed -e "s@{\(.*\)}@$line@" <<< "$format")"
            combs="$combs@$tmp"
        done <<< "$mult"
        combs="$(tr '@' '\n' <<< "$combs")"
    else
        combs="$format"
    fi

    # Now, starts from the first argument, narrows down the
    # subcommand format combinations.
    for arg in "${subcmd_line[@]}"; do
        local kword possible_comps

        # Finds next level possible comps.
        possible_comps=$(find_possible_comps "$combs")
        # Finds the kword.
        kword="$(arg_to_kwords "$arg" "$possible_comps")"
        # Returns if could not find 'kword'
        if [ -z "$kword" ]; then
            return
        fi
        # Trims the 'combs', keeps context only after 'kword'.
        if [ -n "$combs" ]; then
            combs="$(sed -n "s@^.*\[\{0,1\}$kword|\{0,1\}[a-z_]*\]\{0,1\} @@p" <<< "$combs")"
        fi
    done
    comps="$(find_possible_comps "$combs")"

    echo "$comps"
}



# Helper
# ======
#
#
#
# Prints the input to stderr.  $_PRINTF_ENABLE must be filled.
printf_stderr() {
    local stderr_out="$@"

    if [ -n "$_PRINTF_ENABLE" ]; then
        printf "\n$stderr_out" 1>&2
    fi
}

# Extracts the bash prompt PS1, outputs it with the input argument
# via 'printf_stderr'.
#
# Original idea inspired by:
# http://stackoverflow.com/questions/10060500/bash-how-to-evaluate-ps1-ps2
#
# The code below is taken from Peter Amidon.  His change makes it more
# robust.
extract_bash_prompt() {
    local myPS1 v

    myPS1="$(sed 's/Begin prompt/\\Begin prompt/; s/End prompt/\\End prompt/' <<< "$PS1")"
    v="$(bash --norc --noprofile -i 2>&1 <<< $'PS1=\"'"$myPS1"$'\" \n# Begin prompt\n# End prompt')"
    v="${v##*# Begin prompt}"
    _BASH_PROMPT="$(tail -n +2 <<< "${v%# End prompt*}" | sed 's/\\Begin prompt/Begin prompt/; s/\\End prompt/End prompt/')"
}



# Keyword Conversion
# ==================
#
#
#
# All completion functions.
complete_bridge () {
    local result error

    result=$(ovs-vsctl list-br 2>/dev/null | grep -- "^$1") || error="TRUE"

    if [ -z "$error" ]; then
        echo  "${result}"
    fi
}

complete_port () {
    local ports result error
    local all_ports

    all_ports=$(ovs-vsctl --format=table \
        --no-headings \
        --columns=name \
        list Port 2>/dev/null) || error="TRUE"
    ports=$(printf "$all_ports" | sort | tr -d '"' | uniq -u)
    result=$(grep -- "^$1" <<< "$ports")

    if [ -z "$error" ]; then
        echo  "${result}"
    fi
}

complete_iface () {
    local bridge bridges result error

    bridges=$(ovs-vsctl list-br 2>/dev/null) || error="TRUE"
    for bridge in $bridges; do
        local ifaces

        ifaces=$(ovs-vsctl list-ifaces "${bridge}" 2>/dev/null) || error="TRUE"
        result="${result} ${ifaces}"
    done

    if [ -z "$error" ]; then
        echo  "${result}"
    fi
}

complete_dp () {
    local dps result error

    dps=$(ovs-appctl dpctl/dump-dps 2>/dev/null | cut -d '@' -f2) || error="TRUE"
    result=$(grep -- "^$1" <<< "$dps")

    if [ -z "$error" ]; then
        echo  "${result}"
    fi
}

# Converts the argument (e.g. bridge/port/interface/dp name) to
# the corresponding keywords.
# Returns empty string if could not map the arg to any keyword.
arg_to_kwords() {
    local arg="$1"
    local possible_kwords=($2)
    local non_parsables=()
    local match=
    local kword

    for kword in ${possible_kwords[@]}; do
        case "$kword" in
            bridge|switch)
                match="$(complete_bridge "$arg")"
                ;;
            port)
                match="$(complete_port "$arg")"
                ;;
            interface|iface)
                match="$(complete_iface "$arg")"
                ;;
            dp_name|dp)
                match="$(complete_dp "$arg")"
                ;;
            *)
                if [ "$arg" = "$kword" ]; then
                    match="$kword"
                else
                    non_parsables+=("$kword")
                    continue
                fi
                ;;
        esac

        if [ -n "$match" ]; then
            echo "$kword"
            return
        fi
    done

    # If there is only one non-parsable kword,
    # just assumes the user input it.
    if [ "${#non_parsables[@]}" -eq "1" ]; then
        echo "$non_parsables"
        return
    fi
}

# Expands the keywords to the corresponding instance names.
kwords_to_args() {
    local possible_kwords=($@)
    local args=()
    local printf_expand_once=
    local kword

    for kword in ${possible_kwords[@]}; do
        local match=

        case "${kword}" in
            bridge|switch)
                match="$(complete_bridge "")"
                ;;
            port)
                match="$(complete_port "")"
                ;;
            interface|iface)
                match="$(complete_iface "")"
                ;;
            dp_name|dp)
                match="$(complete_dp "")"
                ;;
            -*)
                # Treats option as kword as well.
                match="$kword"
                ;;
            *)
                match=
                ;;
        esac
        match=$(echo "$match" | tr '\n' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//')
        args+=( $match )
        if [ -n "$_PRINTF_ENABLE" ]; then
            local output_stderr=

            if [ -z "$printf_expand_once" ]; then
                printf_expand_once="once"
                printf -v output_stderr "\nArgument expansion:\n"
            fi
            printf -v output_stderr "$output_stderr     available completions \
for keyword \"%s\": %s " "$kword" "$match"

            printf_stderr "$output_stderr"
        fi
    done

    echo "${args[@]}"
}




# Parse and Compgen
# =================
#
#
#
# This function takes the current command line arguments as input,
# finds the command format and returns the possible completions.
parse_and_compgen() {
    local command=$_COMMAND
    local subcmd_line=($@)
    local subcmd=${subcmd_line[0]}
    local target=
    local subcmd_format=
    local comp_keywords=
    local comp_wordlist=

    if [ -n "$_APPCTL_TARGET" ]; then
        target="--target $_APPCTL_TARGET"
    fi

    # Extracts the subcommand format.
    subcmd_format="$($command $target list-commands 2>/dev/null | tail -n +2 | cut -c3- \
                     | awk -v opt=$subcmd '$1 == opt {print $0}' | tr -s ' ' )"

    # Finds the possible completions based on input argument.
    comp_keyword="$(subcmd_find_keyword_based_on_input "$subcmd_format" \
                     "${subcmd_line[@]}")"

    # Prints subcommand format and expands the keywords if 'comp_keyword'
    # is not empty.
    if [ -n "$comp_keyword" ]; then
        printf_stderr "$(printf "\nCommand format:\n%s" "$subcmd_format")"
        comp_wordlist="$(kwords_to_args "$comp_keyword")"
        # If there is no expanded completions, returns "NO_EXPAN" to
        # distinguish from the case of no available completions.
        if [ -z "$comp_wordlist" ]; then
            echo "NO_EXPAN"
        else
            echo "$comp_wordlist"
        fi
    fi
}



# Compgen Helper
# ==============
#
#
#
# Takes the current command line arguments and returns the possible
# completions.
#
# At the beginning, the options are checked and completed.  For ovs-appctl
# completion, The function looks for the --target option which gives the
# target daemon name.  If it is not provided, by default, 'ovs-vswitchd'
# is used.
#
# Then, tries to locate and complete the subcommand.  If the subcommand
# is provided, the following arguments are passed to the 'parse_and_compgen'
# function to figure out the corresponding completion of the subcommand.
#
# Returns the completion arguments on success.
ovs_comp_helper() {
    local cmd_line_so_far=($@)
    local comp_wordlist _subcmd options i
    local j=-1

    # Parse the command-line args till we find the subcommand.
    for i in "${!cmd_line_so_far[@]}"; do
        # if $i is not greater than $j, it means the previous iteration
        # skips not-visited args.  so, do nothing and catch up.
        if [ $i -le $j ]; then continue; fi
        j=$i
        if [[ "${cmd_line_so_far[i]}" =~ ^--*  ]]; then
            # If --target is found, locate the target daemon.
            # Else, it is an option command, fill the comp_wordlist with
            # all options.
            if [ "$_COMMAND" = "ovs-appctl" ] \
                && [[ "${cmd_line_so_far[i]}" =~ ^--target$ ]]; then
                _APPCTL_TARGET="ovs-vswitchd"

                if [ -n "${cmd_line_so_far[j+1]}" ]; then
                    local daemon

                    for daemon in $_POSSIBLE_TARGETS; do
                        # Greps "$daemon" in argument, since the argument may
                        # be the path to the pid file.
                        if [ "$daemon" = "${cmd_line_so_far[j+1]}" ]; then
                            _APPCTL_TARGET="$daemon"
                            ((j++))
                            break
                        fi
                    done
                    continue
                else
                    comp_wordlist="$_POSSIBLE_TARGETS"
                    break
                fi
            else
                options="$(extract_options $_COMMAND)"
                # See if we could find the exact option.
                if [ "${cmd_line_so_far[i]}" = "$(grep -- "${cmd_line_so_far[i]}" <<< "$options")" ]; then
                    # If an argument is required and next argument is non-empty,
                    # skip it.  Else, return directly.
                    if [ -n "$(option_require_arg "${cmd_line_so_far[i]}")" ]; then
                        ((j++))
                        if [ -z "${cmd_line_so_far[j]}" ]; then
                            printf_stderr "\nOption requires an arugment."
                            return
                        fi
                    fi
                    continue
                # Else, need to keep completing on option.
                else
                    comp_wordlist="$options"
                    break
                fi
            fi
        fi
        # Takes the first non-option argument as subcmd.
        _subcmd="${cmd_line_so_far[i]}"
        break
    done

    if [ -z "$comp_wordlist" ]; then
        # If the subcommand is not found, provides all subcmds and options.
        if [ -z "$_subcmd" ]; then
            comp_wordlist="$(extract_subcmds) $(extract_options)"
        # Else parses the current arguments and finds the possible completions.
        else
            # $j stores the index of the subcmd in cmd_line_so_far.
            comp_wordlist="$(parse_and_compgen "${cmd_line_so_far[@]:$j}")"
        fi
    fi

    echo "$comp_wordlist"
}

# Compgen
# =======
#
#
#
# The compgen function.
_ovs_command_complete() {
  local cur prev

  _COMMAND=${COMP_WORDS} # element 0 is the command.
  COMPREPLY=()
  cur=${COMP_WORDS[COMP_CWORD]}

  # Do not print anything at first [TAB] execution.
  if [ "$COMP_TYPE" -eq "9" ]; then
      _PRINTF_ENABLE=
  else
      _PRINTF_ENABLE="enabled"
  fi

  # Extracts bash prompt PS1.
  if [ "$1" != "debug" ]; then
      extract_bash_prompt
  fi

  # Invokes the helper function to get all available completions.
  # Always not input the 'COMP_WORD' at 'COMP_CWORD', since it is
  # the one to be completed.
  _COMP_WORDLIST="$(ovs_comp_helper \
      ${COMP_WORDS[@]:1:COMP_CWORD-1})"

  # This is a hack to prevent autocompleting when there is only one
  # available completion and printf disabled.
  if [ -z "$_PRINTF_ENABLE" ] && [ -n "$_COMP_WORDLIST" ]; then
      _COMP_WORDLIST="$_COMP_WORDLIST none void no-op"
  fi

  if [ -n "$_PRINTF_ENABLE" ] && [ -n "$_COMP_WORDLIST" ]; then
      if [ -n "$(echo $_COMP_WORDLIST | tr ' ' '\n' | sed -e '/NO_EXPAN/d' | grep -- "^$cur")" ]; then
          printf_stderr "\nAvailable completions:\n"
      else
          if [ "$1" != "debug" ]; then
              # If there is no match between '$cur' and the '$_COMP_WORDLIST'
              # prints a bash prompt since the 'complete' will not print it.
              printf_stderr "\n$_BASH_PROMPT${COMP_WORDS[@]}"
          fi
      fi
  fi

  if [ "$1" = "debug" ]; then
      printf_stderr "$(echo $_COMP_WORDLIST | tr ' ' '\n' | sort -u | sed -e '/NO_EXPAN/d' | grep -- "$cur")\n"
  else
      if [ -n "$_COMP_WORDLIST" ]; then
          COMPREPLY=( $(compgen -W "$(echo $_COMP_WORDLIST | tr ' ' '\n' \
                                 | sort -u | sed -e '/NO_EXPAN/d')" -- $cur) )
      else
          compopt -o nospace
          # If there is no completions, just complete on file path.
          _filedir
      fi
  fi

  return 0
}

# Debug mode.
if [ "$1" = "debug" ]; then
    shift
    COMP_TYPE=0
    COMP_WORDS=($@)
    COMP_CWORD="$(expr $# - 1)"

    # If the last argument is TAB, it means that the previous
    # argument is already complete and script should complete
    # next argument which is not input yet.  This hack is for
    # compromising the fact that bash cannot take unquoted
    # empty argument.
    if [ "${COMP_WORDS[$COMP_CWORD]}" = "TAB" ]; then
        COMP_WORDS[$COMP_CWORD]=""
    fi

    _ovs_command_complete "debug"
# Normal compgen mode.
else
    complete -F _ovs_command_complete ovs-appctl
    complete -F _ovs_command_complete ovs-ofctl
    complete -F _ovs_command_complete ovs-dpctl
    complete -F _ovs_command_complete ovsdb-tool
fi
