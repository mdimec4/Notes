#!/bin/sh
ldd  secure_notes.exe | grep /ucrt64 | awk '{print $3}' | xargs -i cp {} .
