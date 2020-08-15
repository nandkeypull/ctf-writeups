#!/usr/bin/env python3

from z3 import *
import subprocess
from os import system
from os.path import isfile
from pwn import *

# Get qemu-arm-static/qemu-aarch64-static binaries from
# https://github.com/multiarch/qemu-user-static/releases
#
# Create docker containers to run ARM images
# docker run -v $(pwd)/qemu-arm-static:/usr/bin/qemu-arm-static -ti arm32v7/debian:stretch-slim bash
# docker run -v $(pwd)/qemu-aarch64-static:/usr/bin/qemu-aarch64-static -it arm64v8/debian:stretch-slim bash
# docker run -v $(pwd)/qemu-ppc64-static:/usr/bin/qemu-ppc64-static -it powerpc64/debian bash
ARM32_DOCKER_ID = "0402afecfea2"
ARM64_DOCKER_ID = "7eb726aaf76d"
POWERPC64_DOCKER_ID = "a6ed9f588453"

ARM = False
ARM64 = False
POWERPC64 = False
def extract_and_rename_bin():
    i = 7
    while True:
        filename = "surprise_bin" + str(i)
        if os.path.isfile(filename):
            i += 1
        else:
            os.system("yes | 7z e surprise && chmod u+x surprise~ && mv surprise~ " + filename)
            print("New binary file is %s" % filename)
            os.system("file " + filename)
            break;

def get_latest_bin():
    i = 7
    while True:
        binname = "surprise_bin" + str(i)
        if isfile(binname):
            i += 1
        else:
            binname = "surprise_bin" + str(i-1)
            break;
    return binname

binname = get_latest_bin()
print("binname is %s" % binname)
# binname = "surprise_bin9"

# Check architecture
arch_check_cmd = "file " + binname
version = subprocess.check_output(arch_check_cmd, shell=True)
print(version)
version_str = str(version)
if "ARM" in version_str:
    print("ARM binary found!")
    ARM = True
    if "aarch64" in version_str:
        print("aarch64 ARM binary found!")
        ARM64 = True
elif "64-bit PowerPC" in version_str:
    print("PowerPC 64 binary found!")
    POWERPC64 = True

if ARM or POWERPC64:
    gdb_cmd = "gdb -n --batch " + binname + " -ex 'x/14wx &xor1' | cut -d':' -f2"
    dump = subprocess.check_output(gdb_cmd, shell=True)
    dump_nums = dump.split()
    check_value = [int(dump_nums[i], 16) for i in range(14)]
else:
    readelf_cmd = "readelf -x .data " + binname +" | head -n8 | tail -n +5 | cut -d' ' -f4,5,6,7"
    dump = subprocess.check_output(readelf_cmd, shell=True)
    print(dump)
    dump_nums = dump.split()
    check_value = [int(dump_nums[i][:2], 16) for i in range(14)]

# Z3
flag = [BitVec('{}'.format(i), 8) for i in range(0xf)]
s = Solver()

print(check_value)
# check_value2 = check_value
s.add((flag[2] ^ flag[0] ^ flag[4]) == check_value[0])
s.add((flag[6] ^ flag[2] ^ flag[4]) == check_value[1])
s.add((flag[8] ^ flag[4] ^ flag[6]) == check_value[2])
s.add((flag[10] ^ flag[6] ^ flag[8]) == check_value[3])
s.add((flag[0xc] ^ flag[8] ^ flag[10]) == check_value[4])
s.add((flag[1] ^ flag[10] ^ flag[0xc]) == check_value[5])
s.add((flag[3] ^ flag[0xc] ^ flag[1]) == check_value[6])
s.add((flag[5] ^ flag[1] ^ flag[3]) == check_value[7])
s.add((flag[7] ^ flag[3] ^ flag[5]) == check_value[8])
s.add((flag[9] ^ flag[5] ^ flag[7]) == check_value[9])
s.add((flag[0xb] ^ flag[7] ^ flag[9]) == check_value[10])
s.add((flag[0xd] ^ flag[9] ^ flag[0xb]) == check_value[11])
s.add((flag[0] ^ flag[0xb] ^ flag[0xd]) == check_value[12])
s.add((flag[2] ^ flag[0xd] ^ flag[0]) == check_value[13])

if s.check() == sat:
    print("Found solution")
    model = s.model()
    flag_str = ''.join([chr(int(str(model[flag[i]]))) for i in range(len(model))])
    print(flag_str)
    s.add(flag[0] != s.model()[flag[0]])
else:
    print("No solution")

# Prep for next iteration
if not ARM and not POWERPC64:
    target = process(binname)
    target.sendline(flag_str)
    print(target.recvline())
    extract_and_rename_bin()
    print("Run me again for x86!")
else:
    if ARM64:
        os.system("docker cp " + binname + " " + ARM64_DOCKER_ID + ":/")
        print("Enter the key in the %s container" % ARM64_DOCKER_ID)
        #docker exec 7eb726aaf76d bash -c 'echo hh0c/IAdooq5rk | ./surprise_bin77'
        os.system("docker exec " + ARM64_DOCKER_ID + " bash -c 'echo " + flag_str + " | ./" + binname + "'")
        os.system("docker cp " + ARM64_DOCKER_ID + ":/surprise .")
        extract_and_rename_bin()
    elif ARM:
        os.system("docker cp " + binname + " " + ARM32_DOCKER_ID + ":/")
        print("Enter the key in the %s container" % ARM32_DOCKER_ID)
        os.system("docker exec " + ARM32_DOCKER_ID + " bash -c 'echo " + flag_str + " | ./" + binname + "'")
        os.system("docker cp " + ARM32_DOCKER_ID + ":/surprise .")
        extract_and_rename_bin()
    elif POWERPC64:
        os.system("docker cp " + binname + " " + POWERPC64_DOCKER_ID + ":/")
        print("Enter the key in the %s container" % POWERPC64_DOCKER_ID)
        os.system("docker exec " + POWERPC64_DOCKER_ID + " bash -c 'echo " + flag_str + " | ./" + binname + "'")
        os.system("docker cp " + POWERPC64_DOCKER_ID + ":/surprise .")
        extract_and_rename_bin()
