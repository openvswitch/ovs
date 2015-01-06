#!/bin/bash
#
# Tests for the ovs-command-compgen.bash
#
# Please run this with ovs-command-compgen.bash script inside
# ovs-sandbox, under the same directory.
#
# For information about running the ovs-sandbox, please refer to
# the tutorial directory.
#
#
#
COMP_OUTPUT=
TMP=
EXPECT=
TEST_RESULT=

TEST_COUNTER=0
TEST_COMMANDS=(ovs-appctl ovs-ofctl ovs-dpctl ovsdb-tool)
TEST_APPCTL_TARGETS=(ovs-vswitchd ovsdb-server ovs-ofctl)

#
# Helper functions.
#
get_command_format() {
    local input="$@"

    echo "$(grep -A 1 "Command format" <<< "$input" | tail -n+2)"
}

get_argument_expansion() {
    local input="$@"

    echo "$(grep -- "available completions for keyword" <<< "$input" | sed -e 's/^[ \t]*//')"
}

get_available_completions() {
    local input="$@"

    echo "$(sed -e '1,/Available/d' <<< "$input" | tail -n+2)"
}

generate_expect_completions() {
    local keyword="$1"
    local completions="$2"

    echo "available completions for keyword \"$keyword\": $completions" \
        | sed -e 's/[ \t]*$//'
}

reset_globals() {
    COMP_OUTPUT=
    TMP=
    EXPECT=
    TEST_RESULT=
}

#
# $1: Test name.
# $2: ok or fail.
#
print_result() {
    (( TEST_COUNTER++ ))
    printf "%2d: %-70s %s\n" "$TEST_COUNTER" "$1" "$2"
}

#
# $1: test stage
# $2: actual
# $3: expect
#
print_error() {
    local stage="$1"
    local actual="$2"
    local expect="$3"

    printf "failed at stage_%s:\n" "$stage"
    printf "actual output: %s\n" "$actual"
    printf "expect output: %s\n" "$expect"
}

#
# Sub-tests.
#
ovs_apptcl_TAB() {
    local target="$1"
    local target_line=
    local comp_output tmp expect

    if [ -n "$target" ]; then
        target_line="--target $target"
    fi
    comp_output="$(bash ovs-command-compgen.bash debug ovs-appctl $target_line TAB 2>&1)"
    tmp="$(get_available_completions "$comp_output")"
    expect="$(ovs-appctl --option | sort | sed -n '/^--.*/p' | cut -d '=' -f1)
$(ovs-appctl $target_line list-commands | tail -n +2 | cut -c3- | cut -d ' ' -f1 | sort)"
    if [ "$tmp" = "$expect" ]; then
        echo "ok"
    else
        echo "fail"
    fi
}

#
# Test preparation.
#
ovs-vsctl add-br br0
ovs-vsctl add-port br0 p1


#
# Begin the test.
#
cat <<EOF

## ------------------------------- ##
## ovs-command-compgen unit tests. ##
## ------------------------------- ##

EOF


# complete ovs-appctl [TAB]
# complete ovs-dpctl  [TAB]
# complete ovs-ofctl  [TAB]
# complete ovsdb-tool [TAB]

for test_command in ${TEST_COMMANDS[@]}; do
    reset_globals

    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ${test_command} TAB 2>&1)"
    TMP="$(get_available_completions "$COMP_OUTPUT")"
    EXPECT="$(${test_command} --option | sort | sed -n '/^--.*/p' | cut -d '=' -f1)
$(${test_command} list-commands | tail -n +2 | cut -c3- | cut -d ' ' -f1 | sort)"
    if [ "$TMP" = "$EXPECT" ]; then
        TEST_RESULT=ok
    else
        TEST_RESULT=fail
    fi

    print_result "complete ${test_command} [TAB]" "$TEST_RESULT"
done


# complete ovs-appctl --tar[TAB]

reset_globals

COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl --tar 2>&1)"
TMP="$(get_available_completions "$COMP_OUTPUT")"
EXPECT="--target"
if [ "$TMP" = "$EXPECT" ]; then
    TEST_RESULT=ok
else
    TEST_RESULT=fail
fi

print_result "complete ovs-appctl --targ[TAB]" "$TEST_RESULT"


# complete ovs-appctl --target [TAB]

reset_globals

COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl --target TAB 2>&1)"
TMP="$(get_available_completions "$COMP_OUTPUT")"
EXPECT="$(echo ${TEST_APPCTL_TARGETS[@]} | tr ' ' '\n' | sort)"
if [ "$TMP" = "$EXPECT" ]; then
    TEST_RESULT=ok
else
    TEST_RESULT=fail
fi

print_result "complete ovs-appctl --target [TAB]" "$TEST_RESULT"


# complete ovs-appctl --target ovs-vswitchd [TAB]
# complete ovs-appctl --target ovsdb-server [TAB]
# complete ovs-appctl --target ovs-ofctl    [TAB]

reset_globals

for target in ${TEST_APPCTL_TARGETS[@]}; do
    target_field="--target $i "

    if [ "$target" = "ovs-ofctl" ]; then
        ovs-ofctl monitor br0 --detach --no-chdir --pidfile
    fi

    TEST_RESULT="$(ovs_apptcl_TAB $target)"

    print_result "complete ovs-appctl ${target_field}[TAB]" "$TEST_RESULT"

    if [ "$target" = "ovs-ofctl" ]; then
        ovs-appctl --target ovs-ofctl exit
    fi
done


# check all subcommand formats

reset_globals

TMP="$(ovs-appctl list-commands | tail -n +2 | cut -c3- | cut -d ' ' -f1 | sort)"

# for each subcmd, check the print of subcmd format
for i in $TMP; do
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl $i TAB 2>&1)"
    tmp="$(get_command_format "$COMP_OUTPUT")"
    EXPECT="$(ovs-appctl list-commands | tail -n+2 | cut -c3- | grep -- "^$i " | tr -s ' ' | sort)"
    if [ "$tmp" = "$EXPECT" ]; then
        TEST_RESULT=ok
    else
        TEST_RESULT=fail
        break
    fi
done

print_result "check all subcommand format" "$TEST_RESULT"


# complex completion check - bfd/set-forwarding
# bfd/set-forwarding [interface] normal|false|true
# test expansion of 'interface'

reset_globals

for i in loop_once; do
    # check the top level completion.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl bfd/set-forwarding TAB 2>&1)"
    TMP="$(get_argument_expansion "$COMP_OUTPUT" | sed -e 's/[ \t]*$//')"
    EXPECT="$(generate_expect_completions "normal" "")
$(generate_expect_completions "false" "")
$(generate_expect_completions "true" "")
$(generate_expect_completions "interface" "p1")"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "1" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # check the available completions.
    TMP="$(get_available_completions "$COMP_OUTPUT" | tr '\n' ' ' | sed -e 's/[ \t]*$//')"
    EXPECT="p1"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "2" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # set argument to 'true', there should be no more completions.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl bfd/set-forwarding true TAB 2>&1)"
    TMP="$(sed -e '/./,$!d' <<< "$COMP_OUTPUT")"
    EXPECT="Command format:
bfd/set-forwarding [interface] normal|false|true"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "3" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # set argument to 'p1', there should still be the completion for booleans.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl bfd/set-forwarding p1 TAB 2>&1)"
    TMP="$(get_argument_expansion "$COMP_OUTPUT" | sed -e 's/[ \t]*$//')"
    EXPECT="$(generate_expect_completions "normal" "")
$(generate_expect_completions "false" "")
$(generate_expect_completions "true" "")"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "4" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # check the available completions.
    TMP="$(get_available_completions "$COMP_OUTPUT" | tr '\n' ' ' | sed -e 's/[ \t]*$//')"
    EXPECT=
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "5" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # set argument to 'p1 false', there should still no more completions.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl bfd/set-forwarding p1 false TAB 2>&1)"
    TMP="$(sed -e '/./,$!d' <<< "$COMP_OUTPUT")"
    EXPECT="Command format:
bfd/set-forwarding [interface] normal|false|true"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "6" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    TEST_RESULT=ok
done

print_result "complex completion check - bfd/set-forwarding" "$TEST_RESULT"


# complex completion check - lacp/show
# lacp/show [port]
# test expansion on 'port'

reset_globals

for i in loop_once; do
    # check the top level completion.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl lacp/show TAB 2>&1)"
    TMP="$(get_argument_expansion "$COMP_OUTPUT" | sed -e 's/[ \t]*$//')"
    EXPECT="$(generate_expect_completions "port" "br0 p1")"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "1" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # check the available completions.
    TMP="$(get_available_completions "$COMP_OUTPUT" | tr '\n' ' ' | sed -e 's/[ \t]*$//')"
    EXPECT="br0 p1"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "2" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # set argument to 'p1', there should be no more completions.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl lacp/show p1 TAB 2>&1)"
    TMP="$(sed -e '/./,$!d' <<< "$COMP_OUTPUT")"
    EXPECT="Command format:
lacp/show [port]"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "3" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    TEST_RESULT=ok
done

print_result "complex completion check - lacp/show" "$TEST_RESULT"


# complex completion check - ofproto/trace
# ofproto/trace {[dp_name] odp_flow | bridge br_flow} [-generate|packet]
# test expansion on 'dp|dp_name' and 'bridge'

reset_globals

for i in loop_once; do
    # check the top level completion.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl ofproto/trace TAB 2>&1)"
    TMP="$(get_argument_expansion "$COMP_OUTPUT" | sed -e 's/[ \t]*$//')"
    EXPECT="$(generate_expect_completions "bridge" "br0")
$(generate_expect_completions "odp_flow" "")
$(generate_expect_completions "dp_name" "ovs-system")"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "1" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # check the available completions.
    TMP="$(get_available_completions "$COMP_OUTPUT" | tr '\n' ' ' | sed -e 's/[ \t]*$//')"
    EXPECT="br0 ovs-system"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "2" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # set argument to 'ovs-system', should go to the dp-name path.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl ofproto/trace ovs-system TAB 2>&1)"
    TMP="$(get_argument_expansion "$COMP_OUTPUT" | sed -e 's/[ \t]*$//')"
    EXPECT="$(generate_expect_completions "odp_flow" "")"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "3" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # check the available completions.
    TMP="$(get_available_completions "$COMP_OUTPUT" | tr '\n' ' ' | sed -e 's/[ \t]*$//')"
    EXPECT=
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "4" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # set odp_flow to some random string, should go to the next level.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl ofproto/trace ovs-system "in_port(123),mac(),ip,tcp" TAB 2>&1)"
    TMP="$(get_argument_expansion "$COMP_OUTPUT" | sed -e 's/[ \t]*$//')"
    EXPECT="$(generate_expect_completions "-generate" "-generate")
$(generate_expect_completions "packet" "")"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "5" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # check the available completions.
    TMP="$(get_available_completions "$COMP_OUTPUT" | tr '\n' ' ' | sed -e 's/[ \t]*$//')"
    EXPECT="-generate"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "6" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # set packet to some random string, there should be no more completions.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl ofproto/trace ovs-system "in_port(123),mac(),ip,tcp" "ABSJDFLSDJFOIWEQR" TAB 2>&1)"
    TMP="$(sed -e '/./,$!d' <<< "$COMP_OUTPUT")"
    EXPECT="Command format:
ofproto/trace {[dp_name] odp_flow | bridge br_flow} [-generate|packet]"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "7" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # set argument to 'br0', should go to the bridge path.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl ofproto/trace br0 TAB 2>&1)"
    TMP="$(get_argument_expansion "$COMP_OUTPUT" | sed -e 's/[ \t]*$//')"
    EXPECT="$(generate_expect_completions "br_flow" "")"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "8" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # check the available completions.
    TMP="$(get_available_completions "$COMP_OUTPUT" | tr '\n' ' ' | sed -e 's/[ \t]*$//')"
    EXPECT=
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "9" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # set argument to some random string, should go to the odp_flow path.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl ofproto/trace "in_port(123),mac(),ip,tcp" TAB 2>&1)"
    TMP="$(get_argument_expansion "$COMP_OUTPUT" | sed -e 's/[ \t]*$//')"
    EXPECT="$(generate_expect_completions "-generate" "-generate")
$(generate_expect_completions "packet" "")"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "10" "$TMP" "$EXPEC"T
        TEST_RESULT=fail
        break
    fi

    # check the available completions.
    TMP="$(get_available_completions "$COMP_OUTPUT" | tr '\n' ' ' | sed -e 's/[ \t]*$//')"
    EXPECT="-generate"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "11" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    TEST_RESULT=ok
done

print_result "complex completion check - ofproto/trace" "$TEST_RESULT"


# complex completion check - vlog/set
# vlog/set {spec | PATTERN:destination:pattern}
# test non expandable arguments

reset_globals

for i in loop_once; do
    # check the top level completion.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl vlog/set TAB 2>&1)"
    TMP="$(get_argument_expansion "$COMP_OUTPUT" | sed -e 's/[ \t]*$//')"
    EXPECT="$(generate_expect_completions "PATTERN:destination:pattern" "")
$(generate_expect_completions "spec" "")"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "1" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # check the available completions.
    TMP="$(get_available_completions "$COMP_OUTPUT" | tr '\n' ' ' | sed -e 's/[ \t]*$//')"
    EXPECT=
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "2" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # set argument to random 'abcd', there should be no more completions.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl vlog/set abcd TAB 2>&1)"
    TMP="$(sed -e '/./,$!d' <<< "$COMP_OUTPUT")"
    EXPECT="Command format:
vlog/set {spec | PATTERN:destination:pattern}"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "3" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    TEST_RESULT=ok
done

print_result "complex completion check - vlog/set" "$TEST_RESULT"


# complete after delete port

reset_globals
ovs-vsctl del-port p1

for i in loop_once; do
    # check match on interface, there should be no available interface expansion.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl bfd/set-forwarding TAB 2>&1)"
    TMP="$(get_argument_expansion "$COMP_OUTPUT" | sed -e 's/[ \t]*$//')"
    EXPECT="$(generate_expect_completions "normal" "")
$(generate_expect_completions "false" "")
$(generate_expect_completions "true" "")
$(generate_expect_completions "interface" "")"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "1" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # check the available completions.
    TMP="$(get_available_completions "$COMP_OUTPUT" | tr '\n' ' ' | sed -e 's/[ \t]*$//')"
    EXPECT=
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "2" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # check match on port, there should be no p1 as port.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl lacp/show TAB 2>&1)"
    TMP="$(get_argument_expansion "$COMP_OUTPUT" | sed -e 's/[ \t]*$//')"
    EXPECT="$(generate_expect_completions "port" "br0")"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "3" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # check the available completions.
    TMP="$(get_available_completions "$COMP_OUTPUT" | tr '\n' ' ' | sed -e 's/[ \t]*$//')"
    EXPECT="br0"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "4" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    TEST_RESULT=ok
done

print_result "complete after delete port" "$TEST_RESULT"


# complete after delete bridge

reset_globals
ovs-vsctl del-br br0
for i in loop_once; do
    # check match on port, there should be no p1 as port.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl bridge/dump-flows TAB 2>&1)"
    TMP="$(get_argument_expansion "$COMP_OUTPUT" | sed -e 's/[ \t]*$//')"
    EXPECT="$(generate_expect_completions "bridge" "")"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "1" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # check the available completions.
    TMP="$(get_available_completions "$COMP_OUTPUT" | tr '\n' ' ' | sed -e 's/[ \t]*$//')"
    EXPECT=
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "2" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    # check 'ovs-ofctl monitor [misslen] [invalid_ttl] [watch:[...]]', should
    # not show any available completion.
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-ofctl monitor non_exist_br TAB 2>&1)"
    TMP="$(get_argument_expansion "$COMP_OUTPUT" | sed -e 's/[ \t]*$//')"
    EXPECT=
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "3" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    TEST_RESULT=ok
done

print_result "complete after delete bridge" "$TEST_RESULT"


# negative test - incorrect subcommand

reset_globals

for i in loop_once; do
    # incorrect subcommand
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl ERROR 2>&1)"
    TMP="$(echo "$COMP_OUTPUT" | sed -e 's/[ \t]*$//' | sed -e '/./,$!d')"
    EXPECT=
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "1" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl ERROR TAB 2>&1)"
    TMP="$(echo "$COMP_OUTPUT" | sed -e 's/[ \t]*$//' | sed -e '/./!d')"
    EXPECT="Command format:"
    if [ "$TMP" != "$EXPECT" ]; then
        print_error "2" "$TMP" "$EXPECT"
        TEST_RESULT=fail
        break
    fi

    TEST_RESULT=ok
done

print_result "negative test - incorrect subcommand" "$TEST_RESULT"


# negative test - no ovs-vswitchd
# negative test - no ovsdb-server
# negative test - no ovs-ofctl
# should not see any error.

reset_globals
killall ovs-vswitchd ovsdb-server

for i in ${TEST_APPCTL_TARGETS[@]}; do
    for j in loop_once; do
        reset_globals

        daemon="$i"

        # should show no avaiable subcommands.
        COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl --target $daemon TAB 2>&1)"
        TMP="$(get_available_completions "$COMP_OUTPUT")"
        EXPECT="$(ovs-appctl --option | sort | sed -n '/^--.*/p' | cut -d '=' -f1)"
        if [ "$TMP" != "$EXPECT" ]; then
            TEST_RESULT=fail
            break
        fi

        # should not match any input.
        COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovs-appctl --target $daemon ERROR SUBCMD TAB 2>&1)"
        TMP="$(echo "$COMP_OUTPUT" | sed -e 's/[ \t]*$//' | sed -e '/./!d')"
        EXPECT="Command format:"
        if [ "$TMP" != "$EXPECT" ]; then
            TEST_RESULT=fail
            break
        fi

        TEST_RESULT=ok
    done
    print_result "negative test - no $daemon" "$TEST_RESULT"
done


# negative test - do not match on nested option

reset_globals

for i in loop_once; do
    COMP_OUTPUT="$(bash ovs-command-compgen.bash debug ovsdb-tool create TAB 2>&1)"
    TMP="$(get_available_completions "$COMP_OUTPUT")"
    EXPECT=
    if [ "$TMP" != "$EXPECT" ]; then
        TEST_RESULT=fail
        break
    fi

    TEST_RESULT=ok
done

print_result "negative test - do not match on nested option" "$TEST_RESULT"
