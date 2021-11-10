#include <types.h>
#include <kern/errno.h>
#include <kern/unistd.h>
#include <kern/wait.h>
#include <lib.h>
#include <syscall.h>
#include <current.h>
#include <proc.h>
#include <thread.h>
#include <addrspace.h>
#include <copyinout.h>
#include "opt-A2.h"
#if OPT_A2
#include <mips/trapframe.h>
#include <kern/fcntl.h>
#include <synch.h>
#include <vfs.h>
#endif

/* this implementation of sys__exit does not do anything with the exit code */
/* this needs to be fixed to get exit() and waitpid() working properly */

void sys__exit(int exitcode)
{

  struct addrspace *as;
  struct proc *p = curproc;
  /* for now, just include this to keep the compiler from complaining about
     an unused variable */
#if OPT_A2
  if (curproc->parent != NULL)
  {
    lock_acquire(exit_lock);
    exit_codes[curproc->pid] = exitcode;
    cv_signal(curproc->cv, curproc->children_lock);
    lock_release(exit_lock);
  }
#else
  (void)exitcode;
#endif

  DEBUG(DB_SYSCALL, "Syscall: _exit(%d)\n", exitcode);

  KASSERT(curproc->p_addrspace != NULL);
  as_deactivate();
  /*
   * clear p_addrspace before calling as_destroy. Otherwise if
   * as_destroy sleeps (which is quite possible) when we
   * come back we'll be calling as_activate on a
   * half-destroyed address space. This tends to be
   * messily fatal.
   */
  as = curproc_setas(NULL);
  as_destroy(as);

  /* detach this thread from its process */
  /* note: curproc cannot be used after this call */
  proc_remthread(curthread);

  /* if this is the last user process in the system, proc_destroy()
     will wake up the kernel menu thread */
  proc_destroy(p);

  thread_exit();
  /* thread_exit() does not return, so we should never get here */
  panic("return from thread_exit in sys_exit\n");
}

/* stub handler for getpid() system call                */
int sys_getpid(pid_t *retval)
{
  /* for now, this is just a stub that always returns a PID of 1 */
  /* you need to fix this to make it work properly */
#if OPT_A2
  *retval = curproc->pid;
  return (0);
#else
  *retval = 1;
  return (0);
#endif
}

/* stub handler for waitpid() system call                */

int sys_waitpid(pid_t pid,
                userptr_t status,
                int options,
                pid_t *retval)
{
  int exitstatus;
  int result;

  /* this is just a stub implementation that always reports an
     exit status of 0, regardless of the actual exit status of
     the specified process.
     In fact, this will return 0 even if the specified process
     is still running, and even if it never existed in the first place.
     Fix this!
  */

  if (options != 0)
  {
    return (EINVAL);
  }
  /* for now, just pretend the exitstatus is 0 */
#if OPT_A2
  if (curproc->pid == pid)
  {
    *retval = -1;
    return (ECHILD);
  }
  lock_acquire(curproc->children_lock);
  int position = -1;
  struct proc_wrapper *child;
  for (unsigned int i = 0; i < array_num(curproc->children); i++)
  {
    child = array_get(curproc->children, i);
    if (pid == child->pid)
    {
      position = i;
      break;
    }
  }
  if (position == -1)
  {
    lock_release(curproc->children_lock);
    *retval = -1;
    return (ESRCH);
  }
  while (exit_codes[child->pid] == -1)
  {
    cv_wait(child->proc->cv, curproc->children_lock);
  }
  exitstatus = _MKWAIT_EXIT(exit_codes[child->pid]);
  lock_release(curproc->children_lock);
#else
  exitstatus = 0;
#endif
  result = copyout((void *)&exitstatus, status, sizeof(int));
  if (result)
  {
    return (result);
  }
  *retval = pid;
  return (0);
}

#if OPT_A2
int sys_fork(struct trapframe *tf, pid_t *retval)
{
  int error = 0;

  // create a proccess structure
  struct proc *child = proc_create_runprogram(curproc->p_name); // perhaps we want a diff name for child
  KASSERT(child != NULL);

  // create and copy address space
  error = as_copy(curproc->p_addrspace, &(child->p_addrspace));
  KASSERT(error == 0);

  // setup parent/children relationship
  pid_t new_pid = 0;
  proc_createPid(&new_pid);
  child->pid = new_pid;
  KASSERT(child->pid > 0);
  child->parent = curproc;

  struct proc_wrapper *child_wrapper = kmalloc(sizeof(struct proc_wrapper));
  child_wrapper->proc = child;
  child_wrapper->pid = child->pid;
  lock_acquire(exit_lock);
  exit_codes[new_pid] = -1;
  lock_release(exit_lock);
  lock_acquire(curproc->children_lock);
  array_add(curproc->children, child_wrapper, NULL);
  lock_release(curproc->children_lock);

  // Create thread
  struct trapframe *temp_tf = kmalloc(sizeof(struct trapframe));
  KASSERT(temp_tf != NULL);
  *(temp_tf) = *(tf);

  error = thread_fork(child->p_name, child, (void *)&enter_forked_process, temp_tf, (unsigned long)NULL);
  KASSERT(error == 0);

  *retval = child->pid;

  return (0);
}

int sys_execv(userptr_t progname, userptr_t args)
{
  struct vnode *v;
  struct addrspace *as;
  vaddr_t entrypoint, stackptr;
  int result;

  // Copy args
  int args_count = 0;
  char **temp_args = (char **)args;
  while (temp_args[args_count] != NULL)
  {
    args_count++;
  }
  char **kargs = kmalloc((args_count + 1) * sizeof *kargs);
  int i;
  for (i = 0; i < args_count; i++)
  {
    kargs[i] = kmalloc((strlen(temp_args[i]) + 1) * sizeof **kargs);
    result = copyinstr((userptr_t)temp_args[i], kargs[i], strlen(temp_args[i]) + 1, NULL);
    KASSERT(result == 0);
  }
  kargs[i] = NULL;

  // Copy path
  int progname_len = strlen((char *)progname) + 1;
  char *kprogname = kmalloc((progname_len) * sizeof(char));
  result = copyinstr(progname, kprogname, progname_len, NULL);
  KASSERT(result == 0);

  result = vfs_open(kprogname, O_RDONLY, 0, &v);
  if (result)
  {
    return result;
  }
  as = as_create();
  if (as == NULL)
  {
    vfs_close(v);
    return ENOMEM;
  }
  struct addrspace *old_as = curproc_setas(as);
  as_activate();
  result = load_elf(v, &entrypoint);
  if (result)
  {
    /* p_addrspace will go away when curproc is destroyed */
    vfs_close(v);
    return result;
  }
  vfs_close(v);
  result = as_define_stack(as, &stackptr);
  if (result)
  {
    /* p_addrspace will go away when curproc is destroyed */
    return result;
  }

  // Copy to user stack

  vaddr_t *kargs_ptr = kmalloc((args_count + 1) * sizeof(*kargs_ptr));
  kargs_ptr[args_count] = (vaddr_t)NULL;

  for (int i = args_count - 1; i >= 0; --i)
  {
    size_t cur_size = strlen(kargs[i]) + 1;
    size_t roundedSize = ROUNDUP(cur_size, 4);
    stackptr -= roundedSize;
    result = copyoutstr(kargs[i], (userptr_t)stackptr, cur_size, NULL);
    KASSERT(result == 0);
    kargs_ptr[i] = stackptr;
  }

  for (int i = args_count; i >= 0; --i)
  {
    size_t cur_size = sizeof(*kargs_ptr);
    size_t roundedSize = ROUNDUP(cur_size, 4);
    stackptr -= roundedSize;
    result = copyout(&kargs_ptr[i], (userptr_t)stackptr, sizeof(*kargs_ptr));
    KASSERT(result == 0);
  }
  as_destroy(old_as);

  for (int i = 0; i < args_count; i++)
  {
    kfree(kargs[i]);
  }
  kfree(kargs);
  kfree(kargs_ptr);

  enter_new_process(args_count, (userptr_t)stackptr, stackptr, entrypoint);
  return EINVAL;
  // What about ENODEV, ENOTDIR, EISDIR, ENOEXEC and EIO?
}
#endif
