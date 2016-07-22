## malwhere

Lightweight backdoor that operates in the kernel. There is no expectation of userspace component. Its use is for system reentrance when a) primary persistence mechanism is discovered; or b) [this is is the primary persistence mechanism](https://www.youtube.com/watch?v=qmJ2GVOEVFI).

##overview
It exposes a simple interface to the network via a netfilter hook. The idea is to support a few tactical operations and nothing more.
There's no userspace component, no hiding of processes or files. Yield as few indicators of compromise as possible;
so touch userspace as little as possible.

The current implementation expects a (spoofable) UDP packet that follows a simple protocol: ```magic_value:current_key:new_key:command```

##features
* add user to the system
* add ssh pubkey to the root user
* execute userspace commands
* extensible...

##antiforensics
* encrypted payload functions
    * when the backdoor is at rest (not performing an operation), the interesting pieces of payload are encrypted in memory.
      This is accomplished by receiving a command -> decryption -> execution -> re-encryption. The control channel supports OTP--
      each command sent to the backdoor has the option of providing a new key. The need to re-encrypt with a new key goes away
      when diffie-hellmann is implemented for key exchange.
    * this feature isn't useful for an opensource backdoor....um ok. did I mention extensibility?
* userspace command execution isn't picked up by auditd or traditional kprobing
* I'm debating whether to write a LiME memory dump modifier to tamper with accurate memory dumps. Maybe too devious.

##howtodetect
* you'll have a tainted kernel if you "allow signed modules, but don't require them"
    * all legitimate kernel modules will need to be signed for an unsigned module to be noticed
    * you still need to safely get the fact that the kernel is tainted off the system somehow
    * the kernel can be tainted for reasons other than unsigned driver loading, so pay attention to the taint code
* volatility can show you there's a netfilter hook in place. you probably aren't expecting any, so this is usually high signal.
    * you can then reverse this piece of the module, but shouldn't be able to analyze the payload without the key
* unless something like diffie-hellmann is used for key exchange, you can capture the key over the network to decrypt payload
    * so it still means you need memory dump & pcap to analyze the payload
    
##example
Add a public key to the root user's ```/root/.ssh/authorized_keys``` file.

```$ echo 'key:0124812401:1111111111:2' | nc -u $host 8001```

Current key is ```0124812401```. New key becomes ```1111111111```. Get the key wrong, and your kernel oops :)
