#!/bin/sh

hfile=$1

generate_fields_macros () {
    local struct_name=$1
    local line_start
    local num_lines
    local line_end
    local awk_cmd
    local STRUCT

    # line_start is the line number where the definition of the struct begin
    # line_end is the line number where the definition of the struct ends
    line_start=`grep -nw $struct_name $hfile | grep { | cut -d ":" -f1`
    num_lines=`tail -n +${line_start} $hfile | grep -n -m1 } | cut -d ":" -f1`
    line_end=$((line_start+num_lines-1))


    STRUCT=`echo $struct_name | tr [a-z] [A-Z]`
    echo "#define ${STRUCT}_OFFSETOF_SIZEOF_ARR { \\"
    # for all the field lines, including the terminating }, remove ";" and
    # replace with an item of {offsetof, sizeof}.
    # 3 awk fields are for type struct <struct name> and field <field_name>
    # 2 awk fields are for type <type> and field <field_name>
    # else - terminating the array by item {0, 0}
    awk_cmd="'{"
    awk_cmd=$awk_cmd'    if (NF == 3)'
    awk_cmd=$awk_cmd'        print "    {offsetof(struct '"${struct_name}"', "$3"), sizeof("$1,$2")}, \\";'
    awk_cmd=$awk_cmd'    else if (NF == 2)'
    awk_cmd=$awk_cmd'        print "    {offsetof(struct '"${struct_name}"', "$2"), sizeof("   $1")}, \\";'
    awk_cmd=$awk_cmd'    else'
    awk_cmd=$awk_cmd'        print "    {0, 0}}";'
    awk_cmd=$awk_cmd"}'"
    awk -F ";" "NR>${line_start} && NR<=${line_end}"' {print $1}' $hfile | eval "awk $awk_cmd"

    echo
    echo
}

echo "/* Generated automatically from <include/odp-netlink.h> -- do not modify! */"
echo "#ifndef ODP_NETLINK_MACROS_H"
echo "#define ODP_NETLINK_MACROS_H"
echo
echo

generate_fields_macros "ovs_key_ethernet"
generate_fields_macros "ovs_key_ipv4"
generate_fields_macros "ovs_key_ipv6"
generate_fields_macros "ovs_key_tcp"
generate_fields_macros "ovs_key_udp"
generate_fields_macros "ovs_key_sctp"
generate_fields_macros "ovs_key_icmp"
generate_fields_macros "ovs_key_icmpv6"
generate_fields_macros "ovs_key_arp"
generate_fields_macros "ovs_key_nd"
generate_fields_macros "ovs_key_nd_extensions"

echo
echo "#endif"
