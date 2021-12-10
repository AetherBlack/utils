#!/bin/bash

# Usefull files
FILES_ARRAY=(/proc/version /etc/issue /etc/passwd)

# All available files
AVAILABLE_FILES_ARRAY=()

# Usefull command
COMMAND_ARRAY=(hostname uname ps \
env sudo id history ifconfig \
netstat ip find)

# Option for command
declare -A ARGUMENT_HASHTABLE=(["uname"]="-a" ["ps"]="-A" ["sudo"]="-l" ["ip"]="r" \
["nestat"]="-a" ["find"]="/ -type f -perm -4000")

# All available command
AVAILABLE_COMMAND_ARRAY=()

# Get all available command
for command in "${COMMAND_ARRAY[@]}"; do
    which "$command" 1>/dev/null 2>/dev/null && AVAILABLE_COMMAND_ARRAY+=("$command") 
done

# Get all available files
for file in "${FILES_ARRAY[@]}"; do
    test -e "$file" && AVAILABLE_FILES_ARRAY+=("$file")
done

# Print information
for command in "${AVAILABLE_COMMAND_ARRAY[@]}"; do
    echo "[+] $command:"
    $command ${ARGUMENT_HASHTABLE[$command]} 2>/dev/null
done

for file in "${AVAILABLE_FILES_ARRAY[@]}"; do
    echo "[+] $file:"
    cat $file
done
