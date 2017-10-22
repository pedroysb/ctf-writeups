#!/usr/bin/python
import sys
from os import system

print('Welcome to the Warehouse.')
print('Tell me where and what to store. Exit with ".".')
sys.stdout.flush()
system("/home/warehouse/warehouse")
print("Your stuffs were stored! Bye...")
