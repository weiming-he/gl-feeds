#!/bin/bash

output=$1
input=$2

if [ "$output" = "" ] || [ "$input" = "" ];then
    echo "[luajit_host][error]The input parameter is empty"
    exit 1
fi

if [ ! -f "$input" ];then
    echo "[luajit_host][error]The input file does not exist"
    exit 1
fi

export LUA_PATH="${STAGING_DIR_HOSTPKG}/share/luajit-2.1/?.lua;;"
${STAGING_DIR_HOSTPKG}/bin/luajit2 -b $input $output;