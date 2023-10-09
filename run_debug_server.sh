#!/usr/bin/env bash
# Simple shell script that restarts the server whenever it crashes.


# Find the absolute path regardless of where this script is being executed from.
SRC=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
trap 'exit' SIGINT
cd $SRC/src/bin/
while true; do
    ./run_debug_server
    printf "\e[31;1;5mServer crashed, restarting!\e[0m\n"
    sleep 5
done
