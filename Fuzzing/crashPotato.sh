#!/bin/bash

function usage
{
    echo "usage: $1 [1|2]"
    echo "crashes potato using crashfile 1 or 2."
    exit 1
}

if [ "$#" -ne 1 ]; then
    usage $0
else
    if [ "$1" == "0" ]; then
        crashFile="./input1.txt"
    else
        crashFile="./input2.txt"
    fi
    echo "crashing potato in 3..2..1.."
    echo "./potato console < ${crashFile}"
    ./potato console < ${crashFile}
fi
