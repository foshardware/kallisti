#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>
#include <time.h>

void zeroes32(char* secret);

int setuidgid(const char* account);
int changeroot(const char* path);

void taia_now_offset(char * now, unsigned long off);
void taia_now_coarse_offset(char * now, unsigned long off);

struct tap_desc;
typedef struct tap_desc tap_desc_t;
typedef uint8_t MACAddr[6];

tap_desc_t * init_tap();
void finish_tap(tap_desc_t * td);
int32_t tap_get_fd(tap_desc_t * td);
int32_t open_tap(tap_desc_t * td, char * name, int tun);
int32_t close_tap(tap_desc_t * td);
int32_t bring_up_tap(tap_desc_t * td);
int32_t set_mtu(tap_desc_t * td, uint32_t mtu);
int32_t set_ip(tap_desc_t * td, uint32_t ip);
int32_t set_mask(tap_desc_t * td, uint32_t mask);
int32_t get_mac(tap_desc_t * td, MACAddr mac);

struct windivert_desc;
typedef struct windivert_desc windivert_desc_t;

windivert_desc_t * windivert_open
  ( const char * filter
  , int32_t layer
  , int32_t priority
  , uint32_t flags
  , uint32_t srcAddrRewrite
  );
int32_t windivert_close(windivert_desc_t * wd);
void windivert_set_param(windivert_desc_t * wd, int32_t param, uint32_t value);
int32_t windivert_recv(windivert_desc_t * wd, uint8_t * buf, uint32_t len);
int32_t windivert_send(windivert_desc_t * wd, uint8_t * buf, uint32_t len, uint32_t direction);
