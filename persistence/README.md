## malwhere

Lightweight backdoor that operates in the kernel. There is no expectation of a userspace component. Its use is for system re-entrance when a) primary persistence mechanism is discovered; or b) [this is is the primary persistence mechanism](https://www.youtube.com/watch?v=qmJ2GVOEVFI).

## overview
It exposes a simple interface to the network via a netfilter hook. The idea is to support a few tactical operations and nothing more.
There's no userspace component, no hiding of processes or files. Yield as few indicators of compromise as possible;
so touch userspace as little as possible.

The current implementation expects a UDP packet that follows a simple protocol: ```magic_value:current_key:new_key:command```

## features
* add user to the system
* add ssh pubkey to the root user
* execute userspace commands [not yet implemented]
* extensible...

## antiforensics
* encrypted payload functions
    * when the backdoor is at rest (not performing an operation), the interesting pieces of payload are encrypted in memory.
      This is accomplished by receiving a command -> decryption -> execution -> re-encryption. The control channel supports OTP--
      each command sent to the backdoor has the option of providing a new key. The need to re-encrypt with a new key goes away
      when diffie-hellmann is implemented for key exchange.
    * this feature is only useful when the payload functions are secret. so if these stock functions in sensitive.c are used, there's no point encrypting them.
* userspace command execution isn't picked up by auditd or traditional kprobing
* I'm debating whether to write a LiME memory dump modifier to tamper with accurate memory dumps. Maybe too devious.

## howtodetect
* you'll have a tainted kernel if you "allow signed modules, but don't require them"
    * all legitimate kernel modules will need to be signed for an unsigned module to be noticed
    * you still need to safely (remotely) log the fact that the kernel is tainted somehow
    * the kernel can be tainted for reasons other than unsigned driver loading, so pay attention to the taint code
* a tool like Volatility can show you there's a netfilter hook in place. You probably aren't expecting any, so this is usually high signal.
    * you can then extract and reverse parts of the module, but shouldn't be able to analyze the payload without the key
* unless something like diffie-hellmann is used for key exchange, you can capture the key over the network to decrypt payload
    * you still need a pcap and memory dump to decrypt and analyze the payload
    
## examples
1. Add a public key to the root user's ```/root/.ssh/authorized_keys``` file.

    ```bash
    # Current (decryption) key is ```97425196```. New (re-encryption) key becomes ```12341234```.
    # Get the decryption key wrong, and 95% chance the kernel will oops.
    $ echo -n 'key:97425196:12341234:2' | nc -u $host 8001
    ```
