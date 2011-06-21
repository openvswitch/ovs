#!/bin/bash

# kmodtool - Helper script for building kernel module RPMs
# Copyright (c) 2003-2008 Ville Skyttä <ville.skytta@iki.fi>,
#                         Thorsten Leemhuis <fedora@leemhuis.info>
#                         Jon Masters <jcm@redhat.com>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

shopt -s extglob

myprog="kmodtool"
myver="0.10.10_kmp3"
knownvariants=@(BOOT|PAE|@(big|huge)mem|debug|enterprise|kdump|?(large)smp|uml|xen[0U]?(-PAE)|xen)
kmod_name=
kver=
verrel=
variant=
kmp=

get_verrel ()
{
  verrel=${1:-$(uname -r)}
  verrel=${verrel%%$knownvariants}
}

print_verrel ()
{
  get_verrel $@
  echo "${verrel}"
}

get_variant ()
{
  get_verrel $@
  variant=${1:-$(uname -r)}
  variant=${variant##$verrel}
  variant=${variant:-'""'}
}

print_variant ()
{
  get_variant $@
  echo "${variant}"
}

get_rpmtemplate ()
{
    local variant="${1}"
    local dashvariant="${variant:+-${variant}}"
    case "$verrel" in
        *.el*) kdep="kernel${dashvariant}-%{_target_cpu} = ${verrel}" ;;
        *.EL*) kdep="kernel${dashvariant}-%{_target_cpu} = ${verrel}" ;;
        *)     kdep="kernel-%{_target_cpu} = ${verrel}${variant}"     ;;
    esac

    echo "%package       -n kmod-${kmod_name}${dashvariant}"

    if [ -z "$kmp_provides_summary" ]; then
        echo "Summary:          ${kmod_name} kernel module(s)"
    fi

    if [ -z "$kmp_provides_group" ]; then
        echo "Group:            System Environment/Kernel"
    fi

    if [ ! -z "$kmp_version" ]; then
        echo "Version: %{kmp_version}"
    fi

    if [ ! -z "$kmp_release" ]; then
        echo "Release: %{kmp_release}"
    fi
    
    if [ ! -z "$kmp" ]; then
        echo "%global _use_internal_dependency_generator 0"
    fi
    
    cat <<EOF
Provides:         kernel-modules = ${verrel}${variant}
Provides:         ${kmod_name}-kmod = %{?epoch:%{epoch}:}%{version}-%{release}
EOF
    
    if [ -z "$kmp" ]; then
        echo "Requires:         ${kdep}"
    fi

#
# RHEL5 - Remove common package requirement on general kmod packages.
# Requires: ${kmod_name}-kmod-common >= %{?epoch:%{epoch}:}%{version}
#

    cat <<EOF
Requires(post):   /sbin/depmod
Requires(postun): /sbin/depmod
EOF

if [ "no" != "$kmp_nobuildreqs" ]
then
    echo "BuildRequires: kernel${dashvariant}-devel-%{_target_cpu} = ${verrel}"
fi

if [ "" != "$kmp_override_preamble" ]
then
    cat "$kmp_override_preamble"
fi

cat <<EOF
%description   -n kmod-${kmod_name}${dashvariant}
This package provides the ${kmod_name} kernel modules built for the Linux
kernel ${verrel}${variant} for the %{_target_cpu} family of processors.
%post          -n kmod-${kmod_name}${dashvariant}
if [ -e "/boot/System.map-${verrel}${variant}" ]; then
    /sbin/depmod -aeF "/boot/System.map-${verrel}${variant}" "${verrel}${variant}" > /dev/null || :
fi
EOF
    
    if [ ! -z "$kmp" ]; then
        cat <<EOF

#modules=( \$(rpm -ql kmod-${kmod_name}${dashvariant} | grep '\.ko$') )
modules=( \$(find /lib/modules/${verrel}${variant}/extra/${kmod_name} \
          | grep '\.ko$') )
if [ -x "/sbin/weak-modules" ]; then
    printf '%s\n' "\${modules[@]}" \
    | /sbin/weak-modules --add-modules
fi
%preun         -n kmod-${kmod_name}${dashvariant}
rpm -ql kmod-${kmod_name}${dashvariant} | grep '\.ko$' \
    > /var/run/rpm-kmod-${kmod_name}${dashvariant}-modules
EOF
        
    fi
    
    cat <<EOF
%postun        -n kmod-${kmod_name}${dashvariant}
/sbin/depmod -aF /boot/System.map-${verrel}${variant} ${verrel}${variant} &> /dev/null || :
EOF
    
    if [ ! -z "$kmp" ]; then
        cat <<EOF
modules=( \$(cat /var/run/rpm-kmod-${kmod_name}${dashvariant}-modules) )
#rm /var/run/rpm-kmod-${kmod_name}${dashvariant}-modules
if [ -x "/sbin/weak-modules" ]; then
    printf '%s\n' "\${modules[@]}" \
    | /sbin/weak-modules --remove-modules
fi
EOF
    fi

echo "%files         -n kmod-${kmod_name}${dashvariant}"

if [ "" == "$kmp_override_filelist" ];
then
    echo "%defattr(644,root,root,755)"
    echo "/lib/modules/${verrel}${variant}/"
    echo "%config /etc/depmod.d/kmod-${kmod_name}.conf"
    #BZ252188 - I've commented this out for the moment since RHEL5 doesn't
    #           really support external firmware e.g. at install time. If
    #           you really want it, use an override filelist solution.
    #echo "/lib/firmware/"
else
    cat "$kmp_override_filelist"
fi
}

print_rpmtemplate ()
{
  kmod_name="${1}"
  shift
  kver="${1}"
  get_verrel "${1}"
  shift
  if [ -z "${kmod_name}" ] ; then
    echo "Please provide the kmodule-name as first parameter." >&2
    exit 2
  elif [ -z "${kver}" ] ; then
    echo "Please provide the kver as second parameter." >&2
    exit 2
  elif [ -z "${verrel}" ] ; then
    echo "Couldn't find out the verrel." >&2
    exit 2
  fi
  
  for variant in "$@" ; do
      if [ "default" == "$variant" ];
      then
            get_rpmtemplate ""
      else
            get_rpmtemplate "${variant}"
      fi
  done
}

usage ()
{
  cat <<EOF
You called: ${invocation}

Usage: ${myprog} <command> <option>+
 Commands:
  verrel <uname>                               
    - Get "base" version-release.
  variant <uname>                               
    - Get variant from uname.
  rpmtemplate <mainpgkname> <uname> <variants> 
    - Return a template for use in a source RPM
  rpmtemplate_kmp <mainpgkname> <uname> <variants>
    - Return a template for use in a source RPM with KMP dependencies
  version  
    - Output version number and exit.
EOF
}

invocation="$(basename ${0}) $@"
while [ "${1}" ] ; do
  case "${1}" in
    verrel)
      shift
      print_verrel $@
      exit $?
      ;;
    variant)
      shift
      print_variant $@
      exit $?
      ;;
    rpmtemplate)
      shift
      print_rpmtemplate "$@"
      exit $?
      ;;
    rpmtemplate_kmp)
      shift
      kmp=1
      print_rpmtemplate "$@"
      exit $?
      ;;
    version)
      echo "${myprog} ${myver}"
      exit 0
      ;;
    *)
      echo "Error: Unknown option '${1}'." >&2
      usage >&2
      exit 2
      ;;
  esac
done

# Local variables:
# mode: sh
# sh-indentation: 2
# indent-tabs-mode: nil
# End:
# ex: ts=2 sw=2 et
