# Mr. Robot Vulnerable Machine Write-up

## Overview
The Mr. Robot vulnerable machine is a popular target for penetration testing and cybersecurity training. This write-up documents the steps taken to exploit vulnerabilities and gain access to the system.

## Environment Setup
- **Virtual Machine**: Mr. Robot (IP: 10.10.10.10)
- **Tools Used**: 
  - Nmap
  - Burp Suite
  - Metasploit
  - Netcat

## Enumeration
1. **Network Scanning**: 
   - Conducted a network scan using Nmap to identify open ports and services.
   - Command: `nmap -sS -sV -p- 10.10.10.10`

2. **Service Enumeration**:
   - Identified services running on open ports and their versions.
   - Noted potential vulnerabilities based on service versions.

## Exploitation
1. **Web Application Attack**:
   - Discovered a web application running on port 80.
   - Used Burp Suite to intercept and modify requests.
   - Found an SQL injection vulnerability in the login form.

2. **Gaining Access**:
   - Exploited the SQL injection to bypass authentication and gain access to the admin panel.

3. **Privilege Escalation**:
   - After gaining access, searched for sensitive files and configurations.
   - Found a misconfigured file that allowed for privilege escalation.

## Post-Exploitation
- **Data Exfiltration**: 
  - Retrieved sensitive data from the database.
- **Persistence**: 
  - Created a backdoor for future access.

## Conclusion
The Mr. Robot vulnerable machine provided a comprehensive environment for practicing penetration testing techniques. The vulnerabilities exploited during this exercise highlight the importance of secure coding practices and regular security assessments.

## References
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [Metasploit Documentation](https://docs.metasploit.com/)