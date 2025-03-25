# OS-Assignment-HK242

## How to run

```bash
# Clone the repository
git clone https://github.com/nxhhoang/OS_SystemCallAssignment_HK242.git

# Compile
make all

#Run testcases
./os [test_name]

```

## About
The objective of this assignment is the simulation of major components in a simple operating system, for example, scheduler, synchronization, related operations of physical memory and virtual memory.

## Source Code
This repository is based on the code provided for the assignment. Our requirements were to build:
- Scheduler implement the scheduler that employs MLQ (multilevel queue) policy.
- Memory Management: implement the paging subsystem.
- Systemcall: implement the remaining task of the system call killall. The program name fetching has been provided, students need to figure out the matching processes and terminate their execution (as a common killall command usage).
