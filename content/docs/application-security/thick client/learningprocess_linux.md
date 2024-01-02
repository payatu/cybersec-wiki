---
title: Learning Process - Linux
---

# Learning Resources

## Contents

- [Vulnerability ranking](#owasp-desktop-app-security-top-10)
- [Common Vulnerabilities](#some-common-vulnerabilities)

---
<br>


## OWASP Desktop App Security Top 10

https://owasp.org/www-project-desktop-app-security-top-10/

---
<br>

## Some Common Vulnerabilities

- https://payatu.com/blog/thick-client-penetration-testing/
- https://payatu.com/blog/pentesting-linux-thick-client-applications/


- **Code Execution**
    - https://www.exploit-db.com/exploits/50385
    - https://www.exploit-db.com/exploits/47231
    - https://www.exploit-db.com/exploits/51331 (Via Missing file)

- **Buffer Overflow**
    - https://www.exploit-db.com/exploits/47178

- **Out of bound crash**
    - https://www.exploit-db.com/exploits/35081

- **Forensics**
    - **/proc/[PID]/ directory**
        - https://docs.kernel.org/filesystems/proc.html#:~:text=The%20directory%20%2Fproc%20contains
    - **LD_PRELOAD attack**
        - https://www.goldsborough.me/c/low-level/kernel/2016/08/29/16-48-53-the_-ld_preload-_trick/
    - **Generating and analyzing core dumps**
        - https://opensource.com/article/20/8/linux-dump
        - https://opensource.com/article/20/7/procdump-linux
        - https://www.cse.unsw.edu.au/~learn/debugging/modules/gdb_coredumps/

- **Network traffic analysis**
    - **Traffic capture**
        - https://opensource.com/article/20/1/wireshark-linux-tshark
        - https://opensource.com/article/18/10/introduction-tcpdump
    - **Proxy**
        - https://linuxhint.com/proxychains-tutorial/

- **Privilege Escalation**
    - https://www.exploit-db.com/exploits/51180
    - https://www.exploit-db.com/exploits/50689
