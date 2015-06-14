#!/bin/bash
KERNEL_PATH="/home/nearffxx/tmp/panda"

STRUCTS=("struct epoll_event" "struct iattr" "struct inode" "struct iocb" "struct io_event" "struct iovec" \
 "struct itimerspec" "struct itimerval" "struct kexec_segment" "struct linux_dirent" "struct linux_dirent64" \
 "struct list_head" "struct mmap_arg_struct" "struct msgbuf" "struct user_msghdr" "struct mmsghdr" "struct msqid_ds" \
 "struct new_utsname" "struct nfsctl_arg" "struct __old_kernel_stat" "struct oldold_utsname" "struct old_utsname" \
 "struct pollfd" "struct rlimit" "struct rlimit64" "struct rusage" "struct sched_param" "struct sched_attr" \
 "struct sel_arg_struct" "struct semaphore" "struct sembuf" "struct shmid_ds" "struct sockaddr" "struct stat" "struct stat64" \
 "struct statfs" "struct statfs64" "struct __sysctl_args" "struct sysinfo" "struct timespec" "struct timeval" "struct timex" \
 "struct timezone" "struct tms" "struct utimbuf" "struct mq_attr" "struct compat_stat" "struct compat_timeval" "struct robust_list_head" \
 "struct getcpu_cache" "struct old_linux_dirent" "struct perf_event_attr" "struct file_handle" "struct sigaltstack" "union bpf_attr")

function get_headers()
{
  for i in "${STRUCTS[@]}"
  do
    DEFINITION=`git grep -e "${i} {" -- '*.[h]' | awk '{ print substr($0, 0, length($1)-6) }'`
    if [ -z "$DEFINITION" ]; then
      DEFINITION=`git grep -e "${i} {" -- '*.[c]' | awk '{ print substr($0, 0, length($1)-6) }'`
    fi
    printf "${i}: %s\n" $DEFINITION
  done
}

function main()
{
  echo "Getting ${#STRUCTS[*]} structs..."
  cd $KERNEL_PATH
  get_headers
  echo "Done"
}

main

