#!/bin/sh

schema=$1
sed '/"cksum": *"[0-9][0-9]* [0-9][0-9]*",/d' $schema | cksum
