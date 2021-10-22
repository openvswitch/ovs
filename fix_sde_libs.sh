#! /bin/bash
set -e
if [ -z "$1" ]
then
    echo "- Missing mandatory argument:"
    echo " - Usage: ./fix_paths.sh <SDE_INSTALL_PATH>"
    exit 1
fi
SDE_INSTALL_PATH=$1
la_files=(./install/lib/*.la)
for i in "${la_files[@]}"; do
    echo $i
    libdir=$(awk -F "=" '/libdir/ {print $2}' $i)
    eval lib_dir=$libdir
    existed_install_path="$(dirname "$lib_dir")"
    if [[ "$SDE_INSTALL_PATH" == "$existed_install_path" ]]; then
            echo "paths are matched"
        else
            echo "path does not match.. fixing"
            sed -i "s|$existed_install_path|$SDE_INSTALL_PATH|g" $i
    fi
done
