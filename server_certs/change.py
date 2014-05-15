#!/usr/bin/python

for line in open('list'):
  names = line.rstrip().split('.')
  print names[0] + '.pem'
