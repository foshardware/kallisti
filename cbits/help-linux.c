#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>

#include <netinet/ip.h>

#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include <pwd.h>

#include "help.h"

#define CLEAR(x) \
    memset((x), 0, sizeof(*(x)))


void zeroes32(char* secret) { memset(secret, 0, 32); }

int setuidgid(const char* account)
{
  struct passwd *pw;
  pw = getpwnam(account);
  if (!pw) return 1;
  return setgid(pw->pw_gid) || setuid(pw->pw_uid);
}

int changeroot(const char* path) { return chroot(path); }

void taia_now_offset(char * now, unsigned long off) {
  struct timespec time;
  clock_gettime(CLOCK_REALTIME, &time);
  u_int64_t sec = 4611686018427387914ULL + (u_int64_t)time.tv_sec;
  memcpy(now, &off, 4);
  memcpy(now + 4, &time.tv_nsec, 4);
  memcpy(now + 8, &sec, 8);
  memset(now + 16, 0, 8);
}

void taia_now_coarse_offset(char * now, unsigned long off) {
  struct timespec time;
  clock_gettime(CLOCK_REALTIME_COARSE, &time);
  u_int64_t sec = 4611686018427387914ULL + (u_int64_t)time.tv_sec;
  memcpy(now, &off, 4);
  memcpy(now + 4, &time.tv_nsec, 4);
  memcpy(now + 8, &sec, 8);
  memset(now + 16, 0, 8);
}

struct tap_desc
{
    int32_t      desc;
    int32_t      sock;
    struct ifreq ifr;
};

tap_desc_t * init_tap()
{
    return (tap_desc_t *) calloc(1,sizeof(tap_desc_t));
}

void finish_tap(tap_desc_t * td)
{
    free(td);
}

int32_t tap_get_fd(tap_desc_t * td)
{
    return td->desc;
}

int32_t open_tap(tap_desc_t * td, char * name, int iff)
{
    char * dev = "/dev/net/tun";

    if (0 == td)
    {
        return -100;
    }
    else if (0 == name)
    {
        return -101;
    }

    int32_t fd = open(dev, O_RDWR);

    if (fd < 0)
    {
        fprintf(stderr,"open(%s): %s\n", name, strerror(errno));
        return -1;
    }
    else
    {
        td->desc = fd;
    }

    CLEAR(&(td->ifr));

    td->sock = socket(AF_INET, SOCK_DGRAM, 0);
    td->ifr.ifr_flags = iff | IFF_NO_PI;

    if (*name)
        strncpy(td->ifr.ifr_name, name, IFNAMSIZ);

    if (ioctl(td->desc, TUNSETIFF, (void *)&td->ifr) < 0)
    {
        fprintf(stderr,"TUNSETIFF: %s\n", strerror(errno));
        return -2;
    }

    return 0;
}

int32_t close_tap(tap_desc_t * td)
{
    if (0 <= td->desc)
    {
        close(td->desc);
    }

    return 0;
}

int32_t bring_up_tap(tap_desc_t * td)
{
    td->ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

    if (ioctl(td->sock, SIOCSIFFLAGS, &td->ifr) < 0)
    {
        fprintf(stderr,"SIOCSIFFLAGS: %s\n", strerror(errno));
        return -3;
    }

    return 0;
}

int32_t set_mtu(tap_desc_t * td, uint32_t mtu)
{
    td->ifr.ifr_mtu = mtu;

    if (ioctl(td->sock, SIOCSIFMTU, &td->ifr) < 0)
    {
        fprintf(stderr,"SIOCSIFMTU: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int32_t set_ip(tap_desc_t * td, uint32_t ip)
{
    struct sockaddr_in addr;
    CLEAR(&addr);

    addr.sin_addr.s_addr = ip;
    addr.sin_family = AF_INET;
    memcpy(&td->ifr.ifr_addr, &addr, sizeof(addr));

    if (ioctl(td->sock, SIOCSIFADDR, &td->ifr) < 0)
    {
        fprintf(stderr, "SIOCSIFADDR: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int32_t set_mask(tap_desc_t * td, uint32_t mask)
{
    struct sockaddr_in addr;
    CLEAR(&addr);

    addr.sin_addr.s_addr = mask;
    addr.sin_family = AF_INET;
    memcpy(&td->ifr.ifr_addr, &addr, sizeof(addr));

    if ( ioctl(td->sock, SIOCSIFNETMASK, &td->ifr) < 0)
    {
        fprintf(stderr,"SIOCSIFNETMASK: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int32_t get_mac(tap_desc_t * td, MACAddr mac)
{
    if (ioctl(td->sock, SIOCGIFHWADDR, &td->ifr) < 0)
    {
        fprintf(stderr,"SIOCGIFHWADDR: %s\n", strerror(errno));
        return -1;
    }
    else
    {
        memcpy(mac,&td->ifr.ifr_hwaddr.sa_data, sizeof(MACAddr));
    }

    return 0;
}

struct windivert_desc {};

windivert_desc_t * windivert_open
  ( const char * filter
  , int32_t layer
  , int32_t priority
  , uint32_t flags
  , uint32_t srcAddrRewrite
  ) {
  fprintf(stderr, "WinDivert not implemented for linux; Use tun mode instead.\n");
  return (windivert_desc_t *) calloc(1,sizeof(windivert_desc_t));
}

int32_t windivert_close(windivert_desc_t * wd) { return 0; }

void windivert_set_param(windivert_desc_t * wd, int32_t param, uint32_t value) { }

int32_t windivert_recv(windivert_desc_t * wd, uint8_t * buf, uint32_t len) {
  return -1;
}

int32_t windivert_send(windivert_desc_t * wd, uint8_t * buf, uint32_t len, uint32_t direction) {
  return -1;
}
