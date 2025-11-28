#!/bin/sh
set -e

MODULE="exec_kprobe"

# check if module already loaded
if lsmod | grep -q "^${MODULE}"; then
    echo "[+] Module '${MODULE}' already loaded. Unloading..."
    sudo rmmod ${MODULE}
    sleep 1
fi

echo "[+] Building module..."
make

echo "[+] Loading module..."
sudo insmod ${MODULE}.ko

echo "[+] Done. Recent dmesg:"

dmesg -w

