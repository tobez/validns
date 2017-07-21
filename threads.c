#include <stdlib.h>
#include <stdio.h>
#ifdef __GLIBC__
#include <sys/sysinfo.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

/*  supposedly,
    #if defined(PTW32_VERSION) || defined(__hpux)
        return pthread_num_processors_np();
    but I cannot verify that at the moment
*/

#if defined(__GLIBC__)
int ncpus(void) { return get_nprocs(); }
#elif defined(__APPLE__) || defined(__FreeBSD__)
int ncpus(void)
{
    int count;
    size_t size=sizeof(count);
    return sysctlbyname("hw.ncpu",&count,&size,NULL,0) ? 0 : count;
}
#else
int ncpus(void) { return 0; }  /* "Don't know */
#endif

/*  Supposedly, sysconf() can also be used in some cases:
    #include <unistd.h>
    int const count=sysconf(_SC_NPROCESSORS_ONLN);
    return (count>0)?count:0;
*/
