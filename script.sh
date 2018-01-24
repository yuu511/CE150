#!/bin/bash
FILES=~/test/*
for f in $FILES
do 
  a=0 
  while IFS= read -r LINE; do
    a=$((a+1)) 
    if (( $a % 2 == 0 ))
    then      
      echo "$(basename $f):$LINE"
    fi
  done < "$f"
done
