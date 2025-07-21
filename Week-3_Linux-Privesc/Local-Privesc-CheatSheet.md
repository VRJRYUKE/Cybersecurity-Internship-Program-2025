# Local Privilege Escalation Cheat Sheet

## Common Techniques
- **SUID/GUID Binaries**: Check for binaries with SUID or GUID permissions that can be exploited.
- **Kernel Exploits**: Look for known vulnerabilities in the kernel that can be exploited for privilege escalation.
- **Misconfigured Services**: Identify services running as root that can be manipulated.

## Tools
- **LinPEAS**: A script that searches for possible paths to escalate privileges on Linux.
- **GTFOBins**: A curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions.

## Commands
- **Check SUID Binaries**: 
  ```bash
  find / -perm -4000 -type f 2>/dev/null
  ```
- **Check for Writable Directories**:
  ```bash
  find / -writable -type d 2>/dev/null
  ```
- **Check for Kernel Version**:
  ```bash
  uname -r
  ```

## Privilege Escalation Techniques
- **Environment Variables**: Manipulate environment variables to execute malicious scripts.
- **Cron Jobs**: Check for cron jobs that can be modified to execute commands as root.
- **Path Hijacking**: Modify the PATH variable to execute malicious binaries.

## References
- [GTFOBins](https://gtfobins.github.io/)
- [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)