#!/bin/bash
for i in `seq 1 10`;do
  ./client -h localhost:3490 -u $i
done
