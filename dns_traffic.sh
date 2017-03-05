#!/bin/bash -xv
#echo $1
while [ 1 ]
do
while IFS='' read -r line || [[ -n "$line" ]]; do
   # echo "Text read from file: $line"
   var=" ping -c 1 -w 1 $line 1";
   `$var`
   sleep 0
done < "$1"
done
