#!/usr/bin/python3

import os
import sys

# Print help and exit
def help():
    print("[!] Specify a folder like '/home/user/Documents/chall/.git'")
    exit(1)

# Check the arguments
if len(sys.argv) != 2:
    help()

# Check directory
if not sys.argv[1].endswith(".git"):
    help()

# Change current working directory to .git
os.chdir(sys.argv[1])

# Read recursive commits
def recursiveCommitRead(folder):
    # Change actual directory
    os.chdir(f"./{folder}")
    # For all file in the current directory
    for _file in os.listdir("."):
        # Check if file
        if os.path.isfile(_file):
            # Print information in the stdout
            print(os.popen(f"git show {folder}{_file}").read())
        else:
            # Read if is a folder
            recursiveCommitRead(_file)
    # Go back to the previous directory
    os.chdir("..")

# Launch the function
recursiveCommitRead("objects")