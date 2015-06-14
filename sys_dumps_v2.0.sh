classes="epoll_event iattr inode iocb io_event iovec itimerspec itimerval kexec_segment linux_dirent linux_dirent64 list_head mmap_arg_struct msgbuf msghdr mmsghdr msqid_ds new_utsname nfsctl_arg __old_kernel_stat oldold_utsname old_utsname pollfd rlimit rlimit64 rusage sched_param sel_arg_struct semaphore sembuf shmid_ds sockaddr stat stat64 statfs statfs64 __sysctl_args sysinfo timespec timeval timex timezone tms utimbuf mq_attr compat_stat compat_timeval robust_list_head getcpu_cache old_linux_dirent perf_event_attr file_handle"
"" > sys_struct.h
for class in $classes;
do
  echo $class
  sudo ~/parser/pahole/build/pahole -C $class --expand_types --expand_pointers vmlinux >> sys_struct.h
done
