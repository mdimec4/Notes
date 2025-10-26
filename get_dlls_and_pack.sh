#!/bin/sh
EXE_FILE=./secure_notes.exe

mkdir -p target
ldd  $EXE_FILE | grep $MINGW_PREFIX | awk '{print $3}' | xargs -i cp {} ./target
cp $EXE_FILE ./target