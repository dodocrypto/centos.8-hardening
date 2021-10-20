# [ 0day (xc) Our ] WhiteHat Hacker Team And Dev 2021 
# CENTOS 8.2
# 26/01/2021
# Author : dodocrypto
# Contact : https://discord.me/0dev
# 
# How To Run : python3 ./0dev.Centos8.dev.py and monitor log of /root/0dev.log
# Enough Said Coding time. CENTOS 8.2
# Warning : The Setup Might Be slow as it running configuration and stuff just live it with out canceling it

##### Don't edit below this line unless you know what you are doing
# import neccessary modules
import subprocess    # recommended pipe from python 3.5
import re            # calling regular expressions module
import sys           # calling sys.exit
import datetime      # calling datetime so we can have logs with time



# 1.0 Check if the script is running as root; if not, exit with an error message and abnormal exit code.
with subprocess.Popen(['id'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as process:
    stdout,stderr = process.communicate()
    result = stdout.decode('utf-8')      # convert decode object to string
    root = re.search("^uid=0" , result) 
    if root == None:
        print ("You need root privileges to run this script. Please run this script as the root user or via sudo.")
        sys.exit(1)

# 1.1 Open the log file
try:
    log_0dev = open ('/root/0dev.log' , 'a+')
except:
    print ("/root directory does not exist or you don't have permission to write to it. Please create the directory if it does not exist, otherwise check permissions on /root.")


# 1.2 Update the machine and restart 
with subprocess.Popen(['dnf' , '-y' , 'update'], stdout=subprocess.PIPE,stderr=subprocess.STDOUT) as dnf:
    for line in dnf.stdout:
        result_update = line.decode('utf-8')
        log_0dev.write("%s %s" %(datetime.datetime.now() , result_update))
        log_0dev.flush()
        print (result_update.rstrip())
    log_0dev.write("\n%s ## Finished Updating dnf -y update\n" %(datetime.datetime.now())) 

log_0dev.close()

# 1.3 Declare functions, breaking the script down into subcategories for easy debugging and editing.
def main():                      # Declaring main prototype
    step1()
    step2()
    step3()
    step4()
    step5()
    step6()

def step1():
    with open("/root/0dev.log" , "a+", buffering = 1) as step1:            
        step1.write("\n# Begin Hardening ")
        step1.write ("\n# 1 : Setup Hardening Initial Setup\n# 1.1 : Disable Unused File Systems\n# 1.1.1.1 Ensure mounting of cramfs filesystems is disabled\n")
        with subprocess.Popen(["modprobe" , "-v" , "-r" , "cramfs"], stdout=step1 ) as cramfs:
            stdout,stderr = cramfs.communicate()
    
        step1.write("# 1.1.1.2 Ensure mounting of vFAT filesystems is limited\n")
        with subprocess.Popen(["modprobe" , "-v" , "-r" , "vfat"], stdout=step1 ) as vfat:
            stdout,stderr = vfat.communicate()
    
        step1.write ("# 1.1.1.3 Ensure mounting of squashfs filesystems is disabled\n")
        with subprocess.Popen(["modprobe" , "-v" , "-r" , "squashfs"], stdout=step1 ) as squashfs:
            stdout,stderr = squashfs.communicate()
    
        step1.write("# 1.1.1.4 Ensure mounting of udf filesystems is disabled\n")
        with subprocess.Popen(["modprobe" , "-v" , "-r" , "udf"], stdout=step1 ) as udf:
            stdout,stderr = udf.communicate()

        step1.write("# 1.1.2 - 5 Ensure /tmp is configured\n")
        with subprocess.Popen(["systemctl" , "unmask" , "tmp.mount"], stdout=step1) as tmp1:
            stdout,stderr = tmp1.communicate()
        with subprocess.Popen(["systemctl" , "enable" , "tmp.mount"], stdout=step1) as tmp2:
            stdout,stderr = tmp2.communicate()
        
        with open("/etc/systemd/system/local-fs.target.wants/tmp.mount" , "r" , buffering = 1) as tmp:
                result_tmp = tmp.read()
                result_tmp = result_tmp.rstrip()
                result_tmp = result_tmp.replace("Options=mode=1777,strictatime,nosuid,nodev", "Options=mode=1777,strictatime,noexec,nodev,nosuid")
                tmp.close()
        with open("/etc/systemd/system/local-fs.target.wants/tmp.mount" , "w" , buffering = 1) as tmp:
                tmp.write(result_tmp)
                tmp.close()
        with subprocess.Popen(['systemctl' , 'restart' , 'tmp.mount'], stdout=step1) as tmp3:
            stdout,stderr = tmp3.communicate()
        with subprocess.Popen(['systemctl' , 'daemon-reload'], stdout=step1) as tmp4:
            stdout,stderr = tmp4.communicate()
        step1.write("Success , /tmp mode = Options=mode=1777,strictatime,noexec,nodev,nosuid\n")

        ##### We skipped configuring /home /var/tmp /var /var/log /var/audit. Please do it yourself.
        step1.write("# We skipped configuration of:\n/home\n/var/tmp\n/var\n/var/log\n/var/audit\n\nPlease do it yourself.\n")

        step1.write("# 1.1.21 Ensure sticky bit is set on all world-writable directories\n")
        cmd = "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \)  | xargs -I '{}' chmod a+t '{}'"
        with subprocess.Popen(['/bin/sh', '-c' , cmd] , stdout = step1) as tmp:
            stderr,stdout = tmp.communicate()

        
        step1.write("# 1.1.22 Disable Automounting \n")
        cmd = "systemctl --now disable autofs"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout=step1 ) as tmp6:
            stdout,stderr = tmp6.communicate()
        
        step1.write("# 1.1.23 Disable USB Storage\n")
        cmd = "modprobe -r -v usb-storage"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout=step1) as tmp7:
            stdout,stderr = tmp7.communicate()

        step1.write("# 1.2.2 Ensure gpgcheck is globally activated\n")  
        step1.write("# Ensure /etc/yum.conf gpgcheck set to 1\n")
        cmd = "grep ^gpgcheck /etc/yum.conf"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout=step1) as tmp8:
            stdout,stderr = tmp8.communicate()
        step1.write ("# Ensure all files in /etc/yum.repos.d/ have gpgcheck set to 1\n")
        with subprocess.Popen(['/bin/sh', '-c', 'grep ^gpgcheck /etc/yum.repos.d/*'] , stdout=step1) as tmp_run:
            stdout,stderr = tmp_run.communicate()
            
        
        step1.write("# 1.3.1 Ensure sudo is installed\n")
        cmd = "dnf -y install sudo"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout=step1) as tmp9:
            stderr,stdout = tmp9.communicate()
        
        step1.write("# 1.3.2 Ensure sudo commands use pty\n")
        with open("/etc/sudoers", "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/sudoers", "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\nDefaults use_pty\n")
            tmp.close ()
        
        step1.write("# 1.3.3 Ensure sudo log file exists\n")
        with open("/etc/sudoers", "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/sudoers", "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\nDefaults logfile=\"/var/log/sudo.log\"\n")
            tmp.close ()
        

        step1.write ("# 1.4.1 Ensure AIDE is installed\n")
        cmd = "dnf install -y aide"
        cmd = cmd.split()
        cmd2 = "aide --init"
        cmd2 = cmd2.split()
        cmd3 = "mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
        cmd3 = cmd3.split()
        with subprocess.Popen(cmd, stdout=step1) as tmp10:
            stderr,stdout = tmp10.communicate()
        step1.write ("# Running: aide --init\n")
        with subprocess.Popen(cmd2, stdout=step1) as tmp11:
            stderr,stdout = tmp11.communicate()
        step1.write ("# Renamed new aide db to: /var/lib/aide/aide.db.gz\n")
        with subprocess.Popen(cmd3, stdout=step1) as tmp12:
            stderr,stdout = tmp12.communicate()
        

        step1.write ("# 1.4.2 Ensure filesystem integrity is regularly checked\n")
        cmd = "echo '0 5 * * * /usr/sbin/aide --check' > bash.aide.tmp"
        cmd2 = "crontab -u root bash.aide.tmp"
        cmd2 = cmd2.split()
        cmd3 = "rm -rf bash.aide.tmp"
        cmd3 = cmd3.split()
        with subprocess.Popen(['/bin/bash', '-c' , cmd], stdout=step1) as tmp13:
            stdout,stderr = tmp13.communicate()
        with subprocess.Popen(cmd2, stdout=step1) as tmp14:
            stdout,stderr = tmp14.communicate()
        with subprocess.Popen(cmd3, stdout=step1) as tmp15:
            stdout,stderr = tmp15.communicate()

        step1.write ("# 1.5.1 Ensure permissions on bootloader config are properly configured\n")
        cmd = "chown root:root /boot/grub2/grub.cfg"
        cmd = cmd.split()
        cmd2 = "chmod og-rwx /boot/grub2/grub.cfg"
        cmd2 = cmd2.split()
        cmd3 = "chown root:root /boot/grub2/grubenv"
        cmd3 = cmd3.split()
        cmd4 = "chmod og-rwx /boot/grub2/grubenv"
        cmd4 = cmd4.split()
        with subprocess.Popen(cmd, stdout = step1) as tmp16:
            stdout,stderr = tmp16.communicate()
        with subprocess.Popen(cmd2, stdout = step1) as tmp17:
            stdout,stderr = tmp17.communicate()
        with subprocess.Popen(cmd3, stdout = step1) as tmp18:
            stdout,stderr = tmp18.communicate()
        with subprocess.Popen(cmd4, stdout = step1) as tmp19:
            stdout,stderr = tmp19.communicate()
        step1.write (" Grub config files are now readable only by root\n")

        step1.write("# 1.5.2 Ensure bootloader password is set\n")
        step1.write(" Set it with grub2-setpassword\n")
        step1.write(" And update grub2 with grub2-mkconfig -o /boot/grub2/grub.cfg\n")

        step1.write("# 1.5.3 Ensure authentication is required for single-user mode\n")
        step1.write(" Since it is enabled by default, no configuration is needed\n")

        step1.write("# 1.6.1 Ensure core dumps are restricted\n")
        with open ("/etc/security/limits.conf" , "rt" , buffering = 1 ) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open ("/etc/security/limits.conf" , "wt" , buffering = 1 ) as tmp:
            tmp.write(result_tmp)
            tmp.write("\n* hard core 0\n")
            tmp.close()
        with open ("/etc/sysctl.conf" , "rt" , buffering = 1 ) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open ("/etc/sysctl.conf" , "wt" , buffering = 1 ) as tmp:
            tmp.write(result_tmp)
            tmp.write("\nfs.suid_dumpable = 0\n")
            tmp.close()       
        with subprocess.Popen(["/bin/sh" , "-c" , "sysctl -w fs.suid_dumpable=0"], stdout = step1) as tmp01:
            stdout,stderr = tmp01.communicate()
        
        with open ("/etc/systemd/coredump.conf" , "rt" , buffering = 1 ) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open ("/etc/systemd/coredump.conf" , "wt" , buffering = 1 ) as tmp:
            tmp.write(result_tmp)
            tmp.write("\nStorage=none\n")
            tmp.write("ProcessSizeMax=0\n")
            tmp.close()
        with subprocess.Popen(["/bin/sh" , "-c" , "systemctl daemon-reload"], stdout = step1) as tmp02:
            stdout,stderr = tmp02.communicate()
        
        step1.write("1.6.2 Ensure address space layout randomization (ASLR) is enabled\n")
        with open ("/etc/sysctl.conf" , "rt" , buffering = 1 ) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open ("/etc/sysctl.conf" , "wt" , buffering = 1 ) as tmp:
            tmp.write(result_tmp)
            tmp.write("\nkernel.randomize_va_space = 2\n")
            tmp.close()
        with subprocess.Popen(["/bin/sh" , "-c" , "sysctl -w kernel.randomize_va_space=2"], stdout = step1) as tmp02:
            stdout,stderr = tmp02.communicate()

        step1.write("# 1.7.1.1 Ensure SELinux is installed\n")
        cmd = ("dnf install libselinux")
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout = step1) as tmp20:
            stdout,stderr = tmp20.communicate()
        
        step1.write("# 1.7.1.2 Ensure SELinux is not disabled in bootloader configuration\n")
        step1.write(" Nothing to do as it is enabled by default\n")

        step1.write("# 1.7.1.3 Ensure SELinux policy is configured\n")
        cmd = "sestatus | grep Loaded"       
        with subprocess.Popen(['/bin/sh', '-c' , cmd], stdout = step1) as tmp21:
            stdout,stderr = tmp21.communicate()

        step1.write("# 1.7.1.4 Ensure the SELinux state is enforcing\n")
        cmd = "grep -E '^\s*SELINUX=enforcing' /etc/selinux/config"
        with subprocess.Popen(['/bin/sh' , '-c' , cmd], stdout = step1) as tmp22:
            stdout,stderr = tmp22.communicate()
        
        step1.write("# 1.7.1.6 Ensure SETroubleshoot is not installed\n")
        cmd = "dnf -y remove setroubleshoot"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step1) as tmp23:
            stdout,stderr = tmp23.communicate()
        
        step1.write("# 1.7.1.7 Ensure the MCS Translation Service (mcstrans) is not installed\n")
        cmd = "dnf -y remove mcstrans"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout=step1) as tmp24:
            stdout,stderr = tmp24.communicate()

        step1.write("# 1.8.1.1 Ensure message of the day is configured properly\n")
        cmd = "echo 'Authorized uses only. All activity may be monitored and reported.' > /etc/motd"
        with subprocess.Popen (['/bin/sh' , '-c' , cmd] , stdout = step1) as tmp25:
            stdout,stderr = tmp25.communicate()
        
        step1.write("# 1.8.1.2 Ensure local login warning banner is configured properly\n")
        cmd = "echo 'Authorized uses only. All activity may be monitored and reported.' > /etc/issue"
        with subprocess.Popen (['/bin/sh' , '-c' , cmd] , stdout = step1) as tmp26:
            stdout,stderr = tmp26.communicate()
        
        step1.write("# 1.8.1.3 Ensure remote login warning banner is configured properly\n")
        cmd = "echo 'Authorized uses only. All activity may be monitored and reported.' > /etc/issue.net"
        with subprocess.Popen (['/bin/sh' , '-c' , cmd] , stdout = step1) as tmp27:
            stdout,stderr = tmp27.communicate()

        step1.write("# 1.8.1.4 Ensure permissions on /etc/motd are configured\n")
        cmd = "chown root:root /etc/motd"
        cmd = cmd.split()
        cmd2 = "chmod u-x,go-wx /etc/motd"
        with subprocess.Popen (cmd , stdout = step1) as tmp28:
            stdout,stderr = tmp28.communicate()
        with subprocess.Popen (['/bin/sh' , '-c' , cmd2] , stdout = step1) as tmp29:
            stdout,stderr = tmp29.communicate()

        step1.write("# 1.8.1.5 Ensure permissions on /etc/issue are configured\n")
        cmd = "chown root:root /etc/issue"
        cmd = cmd.split()
        cmd2 = "chmod u-x,go-wx /etc/issue"
        with subprocess.Popen (cmd , stdout = step1) as tmp30:
            stdout,stderr = tmp30.communicate()
        with subprocess.Popen (['/bin/sh' , '-c' , cmd2] , stdout = step1) as tmp31:
            stdout,stderr = tmp31.communicate()
        
        step1.write("# 1.8.1.6 Ensure permissions on /etc/issue.net are configured\n")
        cmd = "chown root:root /etc/issue.net"
        cmd = cmd.split()
        cmd2 = "chmod u-x,go-wx /etc/issue.net"
        with subprocess.Popen (cmd , stdout = step1) as tmp32:
            stdout,stderr = tmp32.communicate()
        with subprocess.Popen (['/bin/sh' , '-c' , cmd2] , stdout = step1) as tmp33:
            stdout,stderr = tmp33.communicate()
        
        step1.write("# 1.10 Ensure system-wide crypto policy is not legacy\n")
        cmd = "update-crypto-policies --set FUTURE"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step1) as tmp34:
            stdout,stderr = tmp34.communicate()

        

def step2():
    with open ("/root/0dev.log" , "a+" , buffering = 1) as step2:
        step2.write("# 2.1.1 Ensure xinetd is not installed\n")
        cmd = "dnf -y remove xinetd"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2 ) as tmp1:
            stdout,stderr = tmp1.communicate()
        
        step2.write("# 2.2.1.1 Ensure time synchronization is in use\n")
        cmd = "dnf -y install chrony"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout = step2) as tmp2:
            stdout,stderr = tmp2.communicate()

        step2.write("# 2.2.1.2 Ensure chrony is configured \n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'grep -E "^(server|pool)" /etc/chrony.conf'], stdout = step2) as tmp3:
            stdout,stderr = tmp3.communicate()
        step2.flush()
        
        step2.write("# 2.2.2 Ensure X Window System is not installed\n")
        cmd = "dnf -y  --exclude python36 remove xorg-x11*"
        cmd = cmd.split()
        cmd2 = "dnf -y install python3"
        cmd2 = cmd2.split()
        with subprocess.Popen(cmd,stdout = step2) as tmp4:
            stdout,stderr = tmp4.communicate()
        with subprocess.Popen(cmd2, stdout = step2) as tmp5:
            stderr,stdout = tmp5.communicate()

        step2.write("# 2.2.3 Ensure rsync service is not enabled\n")
        cmd = "systemctl --now disable rsyncd"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2) as tmp6:
            stdout,stderr = tmp6.communicate()

        step2.write("# 2.2.4 Ensure Avahi Server is not enabled\n")
        cmd = "systemctl --now disable avahi-daemon"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout = step2 ) as tmp7:
            stdout,stderr = tmp7.communicate()

        step2.write("# 2.2.5 Ensure SNMP Server is not enabled\n")
        cmd = "systemctl --now disable snmpd"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2) as tmp8:
            stderr,stdout = tmp8.communicate()
        
        step2.write("# 2.2.6 Ensure HTTP Proxy Server is not enabled\n")
        cmd = "systemctl --now disable squid"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout = step2 ) as tmp9:
            stdout,stderr = tmp9.communicate()

        step2.write("# 2.2.7 Ensure Samba is not enabled\n")
        cmd = "systemctl --now disable smb"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout = step2) as tmp10:
            stderr,stdout = tmp10.communicate()
        
        step2.write("# 2.2.8 Ensure the IMAP and POP3 server is not enabled\n")
        cmd = "systemctl --now disable dovecot"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2) as tmp11:
            stdout,stderr = tmp11.communicate()

        step2.write("# 2.2.9 Ensure HTTP server is not enabled\n")
        cmd = "systemctl --now disable httpd"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2) as tmp12:
            stdout,stderr = tmp12.communicate()

        step2.write("# 2.2.10 Ensure FTP Server is not enabled\n")
        cmd = "systemctl --now disable vsftpd"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2) as tmp13:
            stdout,stderr = tmp13.communicate()
        
        step2.write("# 2.2.11 Ensure DNS Server is not enabled\n")
        cmd = "systemctl --now disable named"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2) as tmp14:
            stdout,stderr = tmp14.communicate()
        
        step2.write("# 2.2.12 Ensure NFS is not enabled\n")
        cmd = "systemctl --now disable nfs"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2) as tmp15:
            stdout,stderr = tmp15.communicate()
        
        step2.write("# 2.2.13 Ensure RPC is not enabled\n")
        cmd = "systemctl --now disable rpcbind"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2) as tmp16:
            stdout,stderr = tmp16.communicate()
        
        step2.write("# 2.2.14 Ensure LDAP server is not enabled\n")
        cmd = "systemctl --now disable slapd"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2) as tmp17:
            stdout,stderr = tmp17.communicate()
        
        # This appears to be a duplicate codeblock, remove?
        step2.write("# 2.2.14 Ensure LDAP server is not enabled\n")
        cmd = "systemctl --now disable slapd"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2) as tmp18:
            stdout,stderr = tmp18.communicate()
        
        step2.write("# 2.2.15 Ensure DHCP Server is not enabled\n")
        cmd = "systemctl --now disable dhcpd"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2) as tmp19:
            stdout,stderr = tmp19.communicate()
        
        step2.write("# 2.2.16 Ensure CUPS is not enabled\n") 
        cmd = "systemctl --now disable cups"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2) as tmp20:
            stdout,stderr = tmp20.communicate()
        
        step2.write("# 2.2.17 Ensure NIS Server is not enabled\n") 
        cmd = "systemctl --now disable ypserv"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2) as tmp21:
            stdout,stderr = tmp21.communicate()
        
        step2.write("# 2.3.1 Ensure NIS Client is not installed\n") 
        cmd = "dnf -y remove ypbind"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2) as tmp22:
            stdout,stderr = tmp22.communicate()
        
        step2.write("# 2.3.2 Ensure telnet client is not installed\n") 
        cmd = "dnf -y remove telnet"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2) as tmp23:
            stdout,stderr = tmp23.communicate()
        
        step2.write("# 2.3.3 Ensure LDAP client is not installed\n") 
        cmd = "dnf -y remove openldap-clients"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2) as tmp24:
            stdout,stderr = tmp24.communicate()
        
        ### Fix any broken packages
        cmd = "dnf -y update"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step2) as tmp25:
            stdout,stderr = tmp25.communicate()

        
def step3():
    with open ("/root/0dev.log" , "a+" , buffering = 1) as step3:
        
        step3.write("# 3.1.1 Ensure IP forwarding is disabled\n")
        with open("/etc/sysctl.conf" , "a" , buffering = 1) as kernel0:
            kernel0.write("net.ipv4.ip_forward = 0\n")
            kernel0.write("net.ipv6.conf.all.forwarding = 0\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.ip_forward=0'] , stdout = step3) as tmp01:
            stdout,stderr = tmp01.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv6.conf.all.forwarding=0'] , stdout = step3) as tmp02:
            stdout,stderr = tmp02.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.route.flush=1'] , stdout = step3) as tmp03:
            stdout,stderr = tmp03.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv6.route.flush=1'] , stdout = step3) as tmp04:
            stdout,stderr = tmp04.communicate()

        step3.write("# 3.1.2 Ensure packet redirect sending is disabled\n")
        with open("/etc/sysctl.conf" , "a" , buffering = 1) as kernel:
            kernel.write("net.ipv4.conf.all.send_redirects = 0\n")
            kernel.write("net.ipv4.conf.default.send_redirects = 0\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.conf.all.send_redirects=0'] , stdout = step3 ) as tmp3:
            stdout,stderr = tmp3.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.conf.default.send_redirects=0'] , stdout = step3 ) as tmp4:
            stdout,stderr = tmp4.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.route.flush=1'] , stdout = step3 ) as tmp5:
            stdout,stderr = tmp5.communicate()
        
        step3.write("# 3.2.1 Ensure source routed packets are not accepted\n")
        with open("/etc/sysctl.conf" , "a" , buffering = 1) as kernel1:
            kernel1.write("net.ipv4.conf.all.accept_source_route = 0\n")
            kernel1.write("net.ipv4.conf.default.accept_source_route = 0\n")
            kernel1.write("net.ipv6.conf.all.accept_source_route = 0\n")
            kernel1.write("net.ipv6.conf.default.accept_source_route = 0\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.conf.all.accept_source_route=0'], stdout = step3 ) as tmp6:
            stdout,stderr = tmp6.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.conf.default.accept_source_route=0'], stdout = step3 ) as tmp7:
            stdout,stderr = tmp7.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv6.conf.all.accept_source_route=0'], stdout = step3 ) as tmp8:
            stdout,stderr = tmp8.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv6.conf.default.accept_source_route=0'], stdout = step3 ) as tmp9:
            stdout,stderr = tmp9.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.route.flush=1'], stdout = step3 ) as tmp10:
            stdout,stderr = tmp10.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv6.route.flush=1'], stdout = step3 ) as tmp11:
            stdout,stderr = tmp11.communicate()
        
        step3.write("# 3.2.2 Ensure ICMP redirects are not accepted\n")
        with open ("/etc/sysctl.conf" , "a" , buffering = 1) as kernel2:
            kernel2.write("net.ipv4.conf.all.accept_redirects = 0\n")
            kernel2.write("net.ipv4.conf.default.accept_redirects = 0\n")
            kernel2.write("net.ipv6.conf.all.accept_redirects = 0\n")
            kernel2.write("net.ipv6.conf.default.accept_redirects = 0\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.conf.all.accept_redirects=0'], stdout = step3) as tmp12:
            stdout,stderr = tmp12.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.conf.default.accept_redirects=0'], stdout = step3) as tmp13:
            stdout,stderr = tmp13.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv6.conf.all.accept_redirects=0'], stdout = step3) as tmp14:
            stdout,stderr = tmp14.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv6.conf.default.accept_redirects=0'], stdout = step3) as tmp15:
            stdout,stderr = tmp15.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.route.flush=1'], stdout = step3) as tmp16:
            stdout,stderr = tmp16.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv6.route.flush=1'], stdout = step3) as tmp17:
            stdout,stderr = tmp17.communicate()
        
        step3.write("# 3.2.3 Ensure secure ICMP redirects are not accepted\n")
        with open ("/etc/sysctl.conf" , "a" , buffering = 1) as kernel3:
             kernel3.write("net.ipv4.conf.all.secure_redirects = 0\n")
             kernel3.write("net.ipv4.conf.default.secure_redirects = 0\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.conf.all.secure_redirects=0'], stdout = step3) as tmp18:
            stdout,stderr = tmp18.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.conf.default.secure_redirects=0'], stdout = step3) as tmp19:
            stdout,stderr = tmp19.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.route.flush=1'], stdout = step3) as tmp20:
            stdout,stderr = tmp20.communicate()
        
        step3.write("# 3.2.4 Ensure suspicious packets are logged\n")
        with open ("/etc/sysctl.conf" , "a" , buffering = 1) as kernel4:
            kernel4.write("net.ipv4.conf.all.log_martians = 1\n")
            kernel4.write("net.ipv4.conf.default.log_martians = 1\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.conf.all.log_martians=1'], stdout = step3) as tmp21:
            stdout,stderr = tmp21.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.conf.default.log_martians=1'], stdout = step3) as tmp22:
            stdout,stderr = tmp22.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.route.flush=1'], stdout = step3) as tmp23:
            stdout,stderr = tmp23.communicate()
        
        step3.write("# 3.2.5 Ensure broadcast ICMP requests are ignored\n")
        with open ("/etc/sysctl.conf" , "a" , buffering = 1) as kernel5:
            kernel5.write("net.ipv4.icmp_echo_ignore_broadcasts = 1\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1'] , stdout = step3) as tmp05:
            stdout,stderr = tmp05.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.route.flush=1'] , stdout = step3) as tmp06:
            stdout,stderr = tmp06.communicate()

        step3.write("# 3.2.6 Ensure bogus ICMP responses are ignored\n")
        with open ("/etc/sysctl.conf" , "a" , buffering = 1) as kernel6:
            kernel6.write("net.ipv4.icmp_ignore_bogus_error_responses = 1\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1'] , stdout = step3) as tmp07:
            stdout,stderr = tmp07.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.route.flush=1'] , stdout = step3) as tmp08:
            stdout,stderr = tmp08.communicate()

        step3.write("# 3.2.7 Ensure Reverse Path Filtering is enabled\n")
        with open ("/etc/sysctl.conf" , "a" , buffering = 1) as kernel7:
            kernel7.write("net.ipv4.conf.default.rp_filter=1\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.conf.default.rp_filter=1'] , stdout = step3) as tmp24:
            stdout,stderr = tmp24.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.route.flush=1'] , stdout = step3) as tmp25:
            stdout,stderr = tmp25.communicate()
        
        step3.write("# 3.2.8 Ensure TCP SYN Cookies is enabled\n")
        with open ("/etc/sysctl.conf" , "a" , buffering = 1) as kernel8:
            kernel8.write("net.ipv4.tcp_syncookies = 1\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.tcp_syncookies=1'] , stdout = step3) as tmp100:
            stdout,stderr = tmp24.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv4.route.flush=1'] , stdout = step3) as tmp101:
            stdout,stderr = tmp25.communicate()
        
        step3.write("# 3.2.9 Ensure IPv6 router advertisements are not accepted\n")
        with open ("/etc/sysctl.conf" , "a" , buffering = 1) as kernel9:
            kernel9.write("net.ipv6.conf.all.accept_ra = 0\n")
            kernel9.write("net.ipv6.conf.default.accept_ra = 0\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv6.conf.all.accept_ra=0'] , stdout = step3) as tmp100:
            stdout,stderr = tmp100.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv6.conf.default.accept_ra=0'] , stdout = step3) as tmp101:
            stdout,stderr = tmp101.communicate()
        with subprocess.Popen(['/bin/sh' , '-c' , 'sysctl -w net.ipv6.route.flush=1=0'] , stdout = step3) as tmp102:
            stdout,stderr = tmp102.communicate()
        
        step3.write("# 3.3.1 Ensure DCCP is disabled\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'modprobe -r -n dccp'] , stdout = step3) as tmp26:
            stdout,stderr = tmp26.communicate()        
        
        step3.write("# 3.3.2 Ensure SCTP is disabled\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'modprobe -r -n sctp'] , stdout = step3) as tmp27:
            stdout,stderr = tmp27.communicate() 
        
        step3.write("# 3.3.3 Ensure RDS is disabled\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'modprobe -r -n rds'] , stdout = step3) as tmp28:
            stdout,stderr = tmp28.communicate() 

        step3.write("# 3.3.4 Ensure TIPC is disabled\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'modprobe -r -n tipc'] , stdout = step3) as tmp29:
            stdout,stderr = tmp29.communicate() 

        step3.write("# 3.4.1.1 Ensure a Firewall package is installed\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'dnf -y install firewalld'] , stdout = step3) as tmp30:
            stdout,stderr = tmp30.communicate()

        step3.write("# 3.4.2.1 Ensure firewalld service is enabled and running\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'systemctl --now enable firewalld'] , stdout = step3) as tmp31:
            stdout,stderr = tmp31.communicate() 

        step3.write("# 3.4.2.2 Ensure nftables is not enabled\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'systemctl --now mask nftables'] , stdout = step3) as tmp32:
            stdout,stderr = tmp32.communicate() 

        step3.write("# 3.4.2.3 Ensure default zone is set\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'firewall-cmd --set-default-zone=public'] , stdout = step3) as tmp33:
            stdout,stderr = tmp33.communicate()
         
           
        step3.write("# 3.4.2.6 Ensure iptables is not enabled\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'systemctl --now mask iptables'] , stdout = step3) as tmp34:
            stdout,stderr = tmp34.communicate()
        
        
        
def step4():
    with open ("/root/0dev.log" , "a+" , buffering = 1 ) as step4:
        
        step4.write("# 4.1.1.1 Ensure auditd is installed\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'dnf -y install audit audit-libs'] , stdout = step4) as tmp1:
            stdout,stderr = tmp1.communicate()
        
        step4.write("# 4.1.1.2 Ensure auditd service is enabled\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'systemctl --now enable auditd'] , stdout = step4) as tmp2:
            stdout,stderr = tmp2.communicate()
                
        step4.write("# 4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled\n")
        with open("/etc/default/grub" , "rt" , buffering = 1) as tmp:
                result_tmp = tmp.read()
                result_tmp = result_tmp.rstrip()
                result_tmp = re.sub('GRUB_CMDLINE.*' , 'GRUB_CMDLINE_LINUX="audit=1 crashkernel=auto resume=/dev/mapper/cl-swap rd.lvm.lv=cl/root rd.lvm.lv=cl/swap rhgb quiet"' , result_tmp )
                tmp.close()
        with open("/etc/default/grub" , "wt" , buffering = 1) as tmp:
                tmp.write(result_tmp)
                tmp.close()
        with subprocess.Popen(['/bin/sh' , '-c' , 'grub2-mkconfig -o /boot/grub2/grub.cfg'] , stdout = step4) as tmp3:
            stdout,stderr = tmp3.communicate()
        
        step4.write("# 4.1.1.4 Ensure audit_backlog_limit is sufficient\n")
        with open("/etc/default/grub" , "rt" , buffering = 1) as tmp:
                result_tmp = tmp.read()
                result_tmp = result_tmp.rstrip()
                result_tmp = re.sub('GRUB_CMDLINE.*' , 'GRUB_CMDLINE_LINUX="audit_backlog_limit=8192 audit=1 crashkernel=auto resume=/dev/mapper/cl-swap rd.lvm.lv=cl/root rd.lvm.lv=cl/swap rhgb quiet"' , result_tmp )
                tmp.close()
        with open("/etc/default/grub" , "wt" , buffering = 1) as tmp:
                tmp.write(result_tmp)
                tmp.close()
        with subprocess.Popen(['/bin/sh' , '-c' , 'grub2-mkconfig -o /boot/grub2/grub.cfg'] , stdout = step4) as tmp4:
            stdout,stderr = tmp4.communicate()

        step4.write("# 4.1.2.1 Ensure audit log storage size is configured to 20 MB\n")
        with open("/etc/audit/auditd.conf" , "rt" , buffering = 1) as tmp:
                result_tmp = tmp.read()
                result_tmp = result_tmp.rstrip()
                result_tmp = re.sub('max_log_file =.*' , 'max_log_file = 20' , result_tmp )
                tmp.close()
        with open("/etc/audit/auditd.conf" , "wt" , buffering = 1) as tmp:
                tmp.write(result_tmp)
                tmp.close()

        step4.write("# 4.1.2.2 Ensure audit logs are not automatically deleted\n")
        with open("/etc/audit/auditd.conf" , "rt" , buffering = 1) as tmp:
                result_tmp = tmp.read()
                result_tmp = result_tmp.rstrip()
                result_tmp = re.sub('max_log_file_action.*' , 'max_log_file_action = keep_logs' , result_tmp )
                tmp.close()
        with open("/etc/audit/auditd.conf" , "wt" , buffering = 1) as tmp:
                tmp.write(result_tmp)
                tmp.close()

        step4.write("# 4.1.2.3 Ensure system is disabled when audit logs are full\n")
        with open("/etc/audit/auditd.conf" , "rt" , buffering = 1) as tmp:
                result_tmp = tmp.read()
                result_tmp = result_tmp.rstrip()
                result_tmp = re.sub('space_left_action.*' , 'space_left_action = email' , result_tmp )
                result_tmp = re.sub('action_mail_acct.*' , 'action_mail_acct = root' , result_tmp )
                result_tmp = re.sub('admin_space_left_action.*' , 'admin_space_left_action = halt' , result_tmp )
                tmp.close()
        with open("/etc/audit/auditd.conf" , "wt" , buffering = 1) as tmp:
                tmp.write(result_tmp)
                tmp.close()
        
        step4.write("# 4.1.3 Ensure changes to system administration scope (sudoers) is collected\n")
        with open("/etc/audit/rules.d/audit.rules" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/audit/rules.d/audit.rules" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("## Ensure changes to sudoers are collected\n")
            tmp.write ("-w /etc/sudoers -p wa -k scope\n")
            tmp.write ("-w /etc/sudoers.d/ -p wa -k scope\n")
            tmp.close()
        
        step4.write("# 4.1.4 Ensure login and logout events are collected\n")
        with open("/etc/audit/rules.d/audit.rules" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/audit/rules.d/audit.rules" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure login and logout events are collected\n")
            tmp.write ("-w /var/log/faillog -p wa -k logins\n")
            tmp.write ("-w /var/log/lastlog -p wa -k logins\n")
            tmp.close()
        
        step4.write("# 4.1.5 Ensure session initiation information is collected\n")
        with open("/etc/audit/rules.d/audit.rules" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/audit/rules.d/audit.rules" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure session initiation information is collected\n")
            tmp.write ("-w /var/run/utmp -p wa -k session\n")
            tmp.write ("-w /var/log/wtmp -p wa -k logins\n")
            tmp.write ("-w /var/log/btmp -p wa -k logins\n")
            tmp.close()
        
        step4.write("# 4.1.6 Ensure events that modify date and time information are collected\n")
        with open("/etc/audit/rules.d/audit.rules" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/audit/rules.d/audit.rules" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure events that modify date and time information are collected\n")
            tmp.write ("-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change\n")
            tmp.write ("-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k timechange\n")
            tmp.write ("-a always,exit -F arch=b64 -S clock_settime -k time-change\n")
            tmp.write ("-a always,exit -F arch=b32 -S clock_settime -k time-change\n")
            tmp.write ("-w /etc/localtime -p wa -k time-change\n")
            tmp.close()
        
        step4.write("# 4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected\n")
        with open("/etc/audit/rules.d/audit.rules" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/audit/rules.d/audit.rules" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure events that modify the system's Mandatory Access Controls are collected\n")
            tmp.write ("-w /etc/selinux/ -p wa -k MAC-policy\n")
            tmp.write ("-w /usr/share/selinux/ -p wa -k MAC-policy\n")
            tmp.close()
        
        step4.write("# 4.1.8 Ensure events that modify the system's network environment are collected\n")
        with open("/etc/audit/rules.d/audit.rules" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/audit/rules.d/audit.rules" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure events that modify the system's network environment are collected\n")
            tmp.write ("-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale\n")
            tmp.write ("-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale\n")
            tmp.write ("-w /etc/issue -p wa -k system-locale\n")
            tmp.write ("-w /etc/issue.net -p wa -k system-locale\n")
            tmp.write ("-w /etc/hosts -p wa -k system-locale\n")
            tmp.write ("-w /etc/sysconfig/network -p wa -k system-locale\n")
            tmp.close()

        step4.write("# 4.1.9 Ensure discretionary access control permission modification events are collected\n")
        with open("/etc/audit/rules.d/audit.rules" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/audit/rules.d/audit.rules" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure discretionary access control permission modification events are collected\n")
            tmp.write ("-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod\n")
            tmp.write ("-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod\n")
            tmp.write ("-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod\n")
            tmp.write ("-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod\n")
            tmp.write ("-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod\n")
            tmp.write ("-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod\n")
            tmp.close()

        step4.write("# 4.1.10 Ensure unsuccessful unauthorized file access attempts are collected\n")
        with open("/etc/audit/rules.d/audit.rules" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/audit/rules.d/audit.rules" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure unsuccessful unauthorized file access attempts are collected\n")
            tmp.write ("-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access\n")
            tmp.write ("-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access\n")
            tmp.write ("-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access\n")
            tmp.write ("-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access\n")
            tmp.close()

        step4.write("# 4.1.11 Ensure events that modify user/group information are collected\n")
        with open("/etc/audit/rules.d/audit.rules" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/audit/rules.d/audit.rules" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure events that modify user/group information are collected\n")
            tmp.write ("-w /etc/group -p wa -k identity\n")
            tmp.write ("-w /etc/passwd -p wa -k identity\n")
            tmp.write ("-w /etc/gshadow -p wa -k identity\n")
            tmp.write ("-w /etc/shadow -p wa -k identity\n")
            tmp.write ("-w /etc/security/opasswd -p wa -k identity\n")
            tmp.close()
        
        step4.write("# 4.1.11 Ensure events that modify user/group information are collected\n")
        with open("/etc/audit/rules.d/audit.rules" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/audit/rules.d/audit.rules" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure events that modify user/group information are collected\n")
            tmp.write ("-w /etc/group -p wa -k identity\n")
            tmp.write ("-w /etc/passwd -p wa -k identity\n")
            tmp.write ("-w /etc/gshadow -p wa -k identity\n")
            tmp.write ("-w /etc/shadow -p wa -k identity\n")
            tmp.write ("-w /etc/security/opasswd -p wa -k identity\n")
            tmp.close()

        step4.write("# 4.1.12 Ensure successful file system mounts are collected \n")
        with open("/etc/audit/rules.d/audit.rules" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/audit/rules.d/audit.rules" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure successful file system mounts are collected\n")
            tmp.write ("-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts\n")
            tmp.write ("-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts\n")
            tmp.close()
        
        step4.write("# 4.1.13 Ensure use of privileged commands is collected\n")
        with open("/etc/audit/rules.d/audit.rules" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/audit/rules.d/audit.rules" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure use of privileged commands is collected\n")
        cmd = """ find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>='"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' -F auid!=4294967295 -k privileged" }' >> /etc/audit/rules.d/audit.rules """
        with subprocess.Popen(['/bin/sh' , '-c' , cmd], stdout = step4 ) as tmp01:
            stdout,stderr = tmp01.communicate()
            tmp.close()
        
        step4.write("# 4.1.14 Ensure file deletion events by users are collected\n")
        with open("/etc/audit/rules.d/audit.rules" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/audit/rules.d/audit.rules" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure file deletion events by users are collected\n")
            tmp.write ("-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete\n")
            tmp.write ("-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete\n")
            tmp.close()
        
        step4.write("# 4.1.15 Ensure kernel module loading and unloading is collected\n")
        with open("/etc/audit/rules.d/audit.rules" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/audit/rules.d/audit.rules" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure kernel module loading and unloading is collected\n")
            tmp.write ("-w /sbin/insmod -p x -k modules\n")
            tmp.write ("-w /sbin/rmmod -p x -k modules\n")
            tmp.write ("-w /sbin/modprobe -p x -k modules\n")
            tmp.write ("-a always,exit -F arch=b64 -S init_module -S delete_module -k modules\n")
            tmp.close()
        
        step4.write("# 4.1.16 Ensure system administrator actions (sudolog) are collected\n")
        with open("/etc/audit/rules.d/audit.rules" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/audit/rules.d/audit.rules" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure system administrator actions (sudolog) are collected\n")
            tmp.write ("-w /var/log/sudo.log -p wa -k actions\n")
            tmp.close()
        
        step4.write("# 4.1.17 Ensure the audit configuration is immutable\n")
        with open("/etc/audit/rules.d/99-finalize.rules" , "wt" , buffering = 1) as tmp:
            tmp.write ("\n## Ensure the audit configuration is immutable\n")
            tmp.write ("-e 2\n")
            tmp.close()
        
        step4.write("# 4.2.1.1 Ensure rsyslog is installed\n")
        cmd = "dnf -y install rsyslog"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step4) as tmp04:
            stderr,stdout = tmp04.communicate()
        
        step4.write("# 4.2.1.2 Ensure rsyslog service is enabled\n")
        cmd = "systemctl --now enable rsyslog"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step4) as tmp05:
            stderr,stdout = tmp05.communicate()
        
        step4.write("# 4.2.1.3 Ensure rsyslog default file permissions are configured properly\n")
        with open("/etc/rsyslog.conf" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/rsyslog.conf" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure rsyslog default file permissions are configured properly\n")
            tmp.write ("$FileCreateMode 0640\n")
            tmp.close()
        cmd = "systemctl restart rsyslog"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step4) as tmp06:
            stderr,stdout = tmp06.communicate()

          
        step4.write("# 4.2.2.1 Ensure journald is configured to send logs to rsyslog\n")
        with open ("/etc/systemd/journald.conf" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/systemd/journald.conf" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure journald is configured to send logs to rsyslog\n")
            tmp.write ("ForwardToSyslog=yes\n")
            tmp.close()
        
        step4.write("# 4.2.2.2 Ensure journald is configured to compress large log files\n")
        with open ("/etc/systemd/journald.conf" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/systemd/journald.conf" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure journald is configured to compress large log files\n")
            tmp.write ("Compress=yes\n")
            tmp.close()
        
        step4.write("# 4.2.2.3 Ensure journald is configured to write logfiles to persistent disk\n")
        with open ("/etc/systemd/journald.conf" , "rt" , buffering = 1) as tmp:
            result_tmp = tmp.read()
            tmp.close()
        with open("/etc/systemd/journald.conf" , "wt" , buffering = 1) as tmp:
            tmp.write (result_tmp)
            tmp.write ("\n## Ensure journald is configured to write logfiles to persistent disk\n")
            tmp.write ("Storage=persistent\n")
            tmp.close()
        
        
def step5():
    with open("/root/0dev.log" , "a+" , buffering=1) as step5:
        step5.write("# 5.1.1 Ensure cron daemon is enabled\n")
        cmd = "systemctl --now enable crond"
        cmd = cmd.split()
        with subprocess.Popen (cmd , stdout = step5) as tmp01:
            stdout,stderr = tmp01.communicate()

        step5.write("# 5.1.2 Ensure permissions on /etc/crontab are configured properly\n")
        cmd = "chown root:root /etc/crontab"
        cmd = cmd.split()
        cmd2 = "chmod og-rwx /etc/crontab"
        cmd2 = cmd2.split()
        with subprocess.Popen (cmd , stdout = step5) as tmp02:
            stdout,stderr = tmp02.communicate()
        with subprocess.Popen (cmd2 , stdout = step5) as tmp03:
            stdout,stderr = tmp03.communicate()
        
        step5.write("# 5.1.3 Ensure permissions on /etc/cron.hourly are configured properly\n")
        cmd = "chown root:root /etc/cron.hourly"
        cmd = cmd.split()
        cmd2 = "chmod og-rwx /etc/cron.hourly"
        cmd2 = cmd2.split()
        with subprocess.Popen (cmd , stdout = step5) as tmp04:
            stdout,stderr = tmp04.communicate()
        with subprocess.Popen (cmd2 , stdout = step5) as tmp05:
            stdout,stderr = tmp05.communicate()

        step5.write("# 5.1.4 Ensure permissions on /etc/cron.daily are configured properly\n")
        cmd = "chown root:root /etc/cron.daily"
        cmd = cmd.split()
        cmd2 = "chmod og-rwx /etc/cron.daily"
        cmd2 = cmd2.split()
        with subprocess.Popen (cmd , stdout = step5) as tmp06:
            stdout,stderr = tmp06.communicate()
        with subprocess.Popen (cmd2 , stdout = step5) as tmp07:
            stdout,stderr = tmp07.communicate()
        
        step5.write("# 5.1.5 Ensure permissions on /etc/cron.weekly are configured properly\n")
        cmd = "chown root:root /etc/cron.weekly"
        cmd = cmd.split()
        cmd2 = "chmod og-rwx /etc/cron.weekly"
        cmd2 = cmd2.split()
        with subprocess.Popen (cmd , stdout = step5) as tmp08:
            stdout,stderr = tmp08.communicate()
        with subprocess.Popen (cmd2 , stdout = step5) as tmp09:
            stdout,stderr = tmp09.communicate()

        step5.write("# 5.1.6 Ensure permissions on /etc/cron.monthly are configured properly\n")
        cmd = "chown root:root /etc/cron.monthly"
        cmd = cmd.split()
        cmd2 = "chmod og-rwx /etc/cron.monthly"
        cmd2 = cmd2.split()
        with subprocess.Popen (cmd , stdout = step5) as tmp10:
            stdout,stderr = tmp10.communicate()
        with subprocess.Popen (cmd2 , stdout = step5) as tmp11:
            stdout,stderr = tmp11.communicate()
        
        step5.write("# 5.1.7 Ensure permissions on /etc/cron.d are configured properly\n")
        cmd = "chown root:root /etc/cron.d"
        cmd = cmd.split()
        cmd2 = "chmod og-rwx /etc/cron.d"
        cmd2 = cmd2.split()
        with subprocess.Popen (cmd , stdout = step5) as tmp12:
            stdout,stderr = tmp12.communicate()
        with subprocess.Popen (cmd2 , stdout = step5) as tmp13:
            stdout,stderr = tmp13.communicate()
        
        step5.write("# 5.1.8 Ensure at/cron is restricted to authorized users\n")
        cmd = "rm -rf /etc/cron.deny"
        cmd = cmd.split()
        cmd2 = "rm -rf /etc/at.deny"
        cmd2 = cmd2.split()
        cmd3 = "touch /etc/cron.allow"
        cmd3 = cmd3.split()
        cmd4 = "touch /etc/at.allow"
        cmd4 = cmd4.split()
        cmd5 = "chmod og-rwx /etc/cron.allow"
        cmd5 = cmd5.split()
        cmd6 = "chmod og-rwx /etc/at.allow"
        cmd6 = cmd6.split()
        cmd7 = "chown root:root /etc/cron.allow"
        cmd7 = cmd7.split()
        cmd8 = "chown root:root /etc/at.allow"
        cmd8 = cmd8.split()
        with subprocess.Popen (cmd , stdout = step5) as tmp14:
            stdout,stderr = tmp14.communicate()
        with subprocess.Popen (cmd2 , stdout = step5) as tmp15:
            stdout,stderr = tmp15.communicate()
        with subprocess.Popen (cmd3 , stdout = step5) as tmp16:
            stdout,stderr = tmp16.communicate()
        with subprocess.Popen (cmd4 , stdout = step5) as tmp17:
            stdout,stderr = tmp17.communicate()
        with subprocess.Popen (cmd5 , stdout = step5) as tmp18:
            stdout,stderr = tmp18.communicate()
        with subprocess.Popen (cmd6 , stdout = step5) as tmp19:
            stdout,stderr = tmp19.communicate()
        with subprocess.Popen (cmd7 , stdout = step5) as tmp20:
            stdout,stderr = tmp20.communicate()
        with subprocess.Popen (cmd8 , stdout = step5) as tmp21:
            stdout,stderr = tmp21.communicate()
        
        step5.write("# 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured properly\n")
        cmd = "chown root:root /etc/ssh/sshd_config"
        cmd = cmd.split()
        cmd2 = "chmod og-rwx /etc/ssh/sshd_config"
        cmd2 = cmd2.split()
        with subprocess.Popen (cmd , stdout = step5) as tmp22:
            stdout,stderr = tmp22.communicate()
        with subprocess.Popen (cmd2 , stdout = step5) as tmp23:
            stdout,stderr = tmp23.communicate()
        
        step5.write("# 5.2.2 Ensure SSH access is limited\n")
        step5.write("### Check ssh and ssh_config man pages for SSH configuration\n")

        step5.write("# 5.2.3 Ensure permissions on SSH private host key files are configured properly\n")
        with subprocess.Popen (['/bin/sh' , '-c' , "find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;"] , stdout = step5) as tmp24:
            stdout,stderr = tmp24.communicate()
        with subprocess.Popen (['/bin/sh' , '-c' , "find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 0600 {} \;"] , stdout = step5) as tmp25:
            stdout,stderr = tmp25.communicate()
        
        step5.write("# 5.2.4 Ensure permissions on SSH public host key files are configured properly\n")
        with subprocess.Popen (['/bin/sh' , '-c' , "find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod 0644 {} \;"] , stdout = step5) as tmp26:
            stdout,stderr = tmp26.communicate()
        with subprocess.Popen (['/bin/sh' , '-c' , "find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;"] , stdout = step5) as tmp27:
            stdout,stderr = tmp27.communicate()
        
        step5.write("# 5.2.5 Ensure SSH LogLevel is set to verbose\n")
        with open ("/etc/ssh/sshd_config" , "rt" , buffering = 1 ) as sshd:
            result_tmp = sshd.read()
            sshd.close()      
        with open ("/etc/ssh/sshd_config" , "wt" , buffering = 1 ) as sshd:
            result_tmp = re.sub(".*LogLevel.*" , "LogLevel VERBOSE" , result_tmp)
            sshd.write(result_tmp)
            sshd.close()

        step5.write("# 5.2.6 Ensure SSH X11 forwarding is disabled\n")
        with open ("/etc/ssh/sshd_config" , "rt" , buffering = 1 ) as sshd:
            result_tmp = sshd.read()
            sshd.close()      
        with open ("/etc/ssh/sshd_config" , "wt" , buffering = 1 ) as sshd:
            result_tmp = re.sub(".*X11Forwarding.*" , "X11Forwarding no" , result_tmp)
            sshd.write(result_tmp)
            sshd.close()
        
        step5.write("# 5.2.7 Ensure SSH MaxAuthTries is set to 4 or less\n")
        with open ("/etc/ssh/sshd_config" , "rt" , buffering = 1 ) as sshd:
            result_tmp = sshd.read()
            sshd.close()      
        with open ("/etc/ssh/sshd_config" , "wt" , buffering = 1 ) as sshd:
            result_tmp = re.sub(".*MaxAuthTries.*" , "MaxAuthTries 4" , result_tmp)
            sshd.write(result_tmp)
            sshd.close()

        step5.write("# 5.2.8 Ensure SSH IgnoreRhosts is enabled\n")
        with open ("/etc/ssh/sshd_config" , "rt" , buffering = 1 ) as sshd:
            result_tmp = sshd.read()
            sshd.close()      
        with open ("/etc/ssh/sshd_config" , "wt" , buffering = 1 ) as sshd:
            result_tmp = re.sub(".*IgnoreRhosts.*" , "IgnoreRhosts yes" , result_tmp)
            sshd.write(result_tmp)
            sshd.close()
        
        step5.write("# 5.2.9 Ensure SSH HostbasedAuthentication is disabled\n")
        with open ("/etc/ssh/sshd_config" , "rt" , buffering = 1 ) as sshd:
            result_tmp = sshd.read()
            sshd.close()      
        with open ("/etc/ssh/sshd_config" , "wt" , buffering = 1 ) as sshd:
            result_tmp = re.sub(".*HostbasedAuthentication.*" , "HostbasedAuthentication no" , result_tmp)
            sshd.write(result_tmp)
            sshd.close()

        step5.write("# 5.2.10 Ensure SSH root login is disabled\n")
        with open ("/etc/ssh/sshd_config" , "rt" , buffering = 1 ) as sshd:
            result_tmp = sshd.read()
            sshd.close()      
        with open ("/etc/ssh/sshd_config" , "wt" , buffering = 1 ) as sshd:
            result_tmp = re.sub(".*PermitRootLogin.*" , "PermitRootLogin no" , result_tmp)
            sshd.write(result_tmp)
            sshd.close()
        
        step5.write("# 5.2.11 Ensure SSH PermitEmptyPasswords is disabled\n")
        with open ("/etc/ssh/sshd_config" , "rt" , buffering = 1 ) as sshd:
            result_tmp = sshd.read()
            sshd.close()      
        with open ("/etc/ssh/sshd_config" , "wt" , buffering = 1 ) as sshd:
            result_tmp = re.sub(".*PermitEmptyPasswords.*" , "PermitEmptyPasswords no" , result_tmp)
            sshd.write(result_tmp)
            sshd.close()
        
        step5.write("# 5.2.12 Ensure SSH PermitUserEnvironment is disabled\n")
        with open ("/etc/ssh/sshd_config" , "rt" , buffering = 1 ) as sshd:
            result_tmp = sshd.read()
            sshd.close()      
        with open ("/etc/ssh/sshd_config" , "wt" , buffering = 1 ) as sshd:
            result_tmp = re.sub(".*PermitUserEnvironment.*" , "PermitUserEnvironment no" , result_tmp)
            sshd.write(result_tmp)
            sshd.close()
        
        step5.write("# 5.2.13 Ensure SSH Idle Timeout Interval is configured\n")
        with open ("/etc/ssh/sshd_config" , "rt" , buffering = 1 ) as sshd:
            result_tmp = sshd.read()
            sshd.close()      
        with open ("/etc/ssh/sshd_config" , "wt" , buffering = 1 ) as sshd:
            result_tmp = re.sub(".*ClientAliveInterval.*" , "ClientAliveInterval 300" , result_tmp)
            result_tmp = re.sub(".*ClientAliveCountMax.*" , "ClientAliveCountMax 0" , result_tmp)
            sshd.write(result_tmp)
            sshd.close()

        step5.write("# 5.2.14 Ensure SSH LoginGraceTime is set to one minute or less\n")
        with open ("/etc/ssh/sshd_config" , "rt" , buffering = 1 ) as sshd:
            result_tmp = sshd.read()
            sshd.close()      
        with open ("/etc/ssh/sshd_config" , "wt" , buffering = 1 ) as sshd:
            result_tmp = re.sub(".*LoginGraceTime.*" , "LoginGraceTime 60" , result_tmp)
            sshd.write(result_tmp)
            sshd.close()
        
        step5.write("# 5.2.15 Ensure SSH warning banner is configured\n")
        with open ("/etc/ssh/sshd_config" , "rt" , buffering = 1 ) as sshd:
            result_tmp = sshd.read()
            sshd.close()      
        with open ("/etc/ssh/sshd_config" , "wt" , buffering = 1 ) as sshd:
            result_tmp = re.sub(".*Banner.*" , "Banner /etc/issue.net" , result_tmp)
            sshd.write(result_tmp)
            sshd.close()
        
        step5.write("# 5.2.16 Ensure SSH PAM is enabled\n")
        with open ("/etc/ssh/sshd_config" , "rt" , buffering = 1 ) as sshd:
            result_tmp = sshd.read()
            sshd.close()      
        with open ("/etc/ssh/sshd_config" , "wt" , buffering = 1 ) as sshd:
            result_tmp = re.sub(".*UsePAM.*" , "UsePAM yes" , result_tmp)
            sshd.write(result_tmp)
            sshd.close()
        
        step5.write("# 5.2.17 Ensure SSH AllowTcpForwarding is disabled\n")
        with open ("/etc/ssh/sshd_config" , "rt" , buffering = 1 ) as sshd:
            result_tmp = sshd.read()
            sshd.close()      
        with open ("/etc/ssh/sshd_config" , "wt" , buffering = 1 ) as sshd:
            result_tmp = re.sub(".*AllowTcpForwarding.*" , "AllowTcpForwarding no" , result_tmp)
            sshd.write(result_tmp)
            sshd.close()
        
        step5.write("# 5.2.18 Ensure SSH MaxStartups is configured\n")
        with open ("/etc/ssh/sshd_config" , "rt" , buffering = 1 ) as sshd:
            result_tmp = sshd.read()
            sshd.close()      
        with open ("/etc/ssh/sshd_config" , "wt" , buffering = 1 ) as sshd:
            sshd.write(result_tmp)
            sshd.write("maxstartups 10:30:60")
            sshd.close()
        
        step5.write("# 5.2.19 Ensure SSH MaxSessions is set to 4 or less\n")
        with open ("/etc/ssh/sshd_config" , "rt" , buffering = 1 ) as sshd:
            result_tmp = sshd.read()
            sshd.close()      
        with open ("/etc/ssh/sshd_config" , "wt" , buffering = 1 ) as sshd:
            result_tmp = re.sub(".*MaxSessions.*" , "MaxSessions 4" , result_tmp)
            sshd.write(result_tmp)
            sshd.close()
        
        step5.write("# 5.2.20 Ensure system-wide crypto policy is not overridden\n")
        with open ("/etc/sysconfig/sshd" , "rt" , buffering = 1 ) as sshd:
            result_tmp = sshd.read()
            sshd.close()      
        with open ("/etc/sysconfig/sshd" , "wt" , buffering = 1 ) as sshd:
            result_tmp = re.sub(".*CRYPTO_POLICY.*" , "# CRYPTO_POLICY" , result_tmp)
            sshd.write(result_tmp)
            sshd.close()

        step5.write("# 5.3.1 Create custom authselect profile\n")
        with subprocess.Popen (['/bin/sh' , '-c' , "authselect create-profile custom-profile -b sssd --symlink-meta"] , stdout = step5) as tmp28:
            stdout,stderr = tmp28.communicate()
        
        step5.write("# 5.3.2 Select authselect profile\n")
        with subprocess.Popen (['/bin/sh' , '-c' , "authselect select custom/custom-profile with-sudo  without-nullok"] , stdout = step5) as tmp29:
            stdout,stderr = tmp29.communicate()

        step5.write("# 5.3.3 Ensure authselect includes with-faillock\n")
        with subprocess.Popen (['/bin/sh' , '-c' , "authselect select custom/custom-profile with-sudo with-faillock without-nullok"] , stdout = step5) as tmp30:
            stdout,stderr = tmp30.communicate()
        
        step5.write("# 5.4.1 Ensure password creation requirements are configured\n")
        with open ("/etc/security/pwquality.conf" , "rt" , buffering = 1 ) as pwquality:
            result_tmp = pwquality.read()
            pwquality.close()      
        with open ("/etc/security/pwquality.conf" , "wt" , buffering = 1 ) as pwquality:
            result_tmp = re.sub(".*minlen.*" , "minlen = 14" , result_tmp)
            result_tmp = re.sub(".*minclass.*" , "minclass = 4" , result_tmp)
            pwquality.write(result_tmp)
            pwquality.close()
        with open ("/etc/authselect/custom/custom-profile/password-auth" , "rt" , buffering = 1 ) as pwquality:
            result_tmp = pwquality.read()
            pwquality = pwquality.close()
        with open ("/etc/authselect/custom/custom-profile/password-auth" , "wt" , buffering = 1 ) as pwquality:
            result_tmp = re.sub(".*password.*requisite.*" , "\npassword    requisite                                    pam_pwquality.so try_first_pass local_users_only enforce-for-root retry=3\n" , result_tmp)
            pwquality.write(result_tmp)
            pwquality.close()
        with open ("/etc/authselect/custom/custom-profile/system-auth" , "rt" , buffering = 1 ) as pwquality:
            result_tmp = pwquality.read()
            pwquality = pwquality.close()
        with open ("/etc/authselect/custom/custom-profile/system-auth" , "wt" , buffering = 1 ) as pwquality:
            result_tmp = re.sub(".*password.*requisite.*" , "\npassword    requisite                                    pam_pwquality.so try_first_pass local_users_only enforce-for-root retry=3\n" , result_tmp)
            pwquality.write(result_tmp)
            pwquality.close()
    
    
        step5.write("# 5.4.2 Ensure lockout for failed password attempts is configured\n")
        with open ("/etc/authselect/custom/custom-profile/password-auth" , "rt" , buffering = 1 ) as pwquality:
            result_tmp = pwquality.read()
            pwquality = pwquality.close()
        with open ("/etc/authselect/custom/custom-profile/password-auth" , "wt" , buffering = 1 ) as pwquality:
            pwquality.write(result_tmp)
            pwquality.write("\nauth required pam_faillock.so preauth silent deny=5 unlock_time=900\n")
            pwquality.write("\nauth required pam_faillock.so authfail deny=5 unlock_time=900\n")
            pwquality.close()
        with open ("/etc/authselect/custom/custom-profile/system-auth" , "rt" , buffering = 1 ) as pwquality:
            result_tmp = pwquality.read()
            pwquality = pwquality.close()
        with open ("/etc/authselect/custom/custom-profile/system-auth" , "wt" , buffering = 1 ) as pwquality:
            pwquality.write(result_tmp)
            pwquality.write("\nauth required pam_faillock.so preauth silent deny=5 unlock_time=900\n")
            pwquality.write("\nauth required pam_faillock.so authfail deny=5 unlock_time=900\n")
            pwquality.close()
    
    
        step5.write("# 5.4.3 Ensure password reuse is limited\n")
        with open ("/etc/authselect/custom/custom-profile/system-auth" , "rt" , buffering = 1 ) as pwquality:
            result_tmp = pwquality.read()
            pwquality = pwquality.close()
        with open ("/etc/authselect/custom/custom-profile/system-auth" , "wt" , buffering = 1 ) as pwquality:
            result_tmp = re.sub(".*password.*requisite.*pam_pwquality.so.*" , "\npassword requisite pam_pwquality.so try_first_pass local_users_only enforce-for-root retry=3 remember=5\n" , result_tmp)
            result_tmp = re.sub(".*password.*sufficient.*pam_unix.so.*" , "\npassword sufficient pam_unix.so sha512 shadow try_first_pass use_authtok remember=5\n" , result_tmp)
            pwquality.write(result_tmp)
            pwquality.close()
    
        step5.write("# 5.4.4 Ensure password hashing algorithm is SHA-512\n")
        with open ("/etc/authselect/custom/custom-profile/password-auth" , "rt" , buffering = 1 ) as pwquality:
            result_tmp = pwquality.read()
            pwquality = pwquality.close()
        with open ("/etc/authselect/custom/custom-profile/password-auth" , "wt" , buffering = 1 ) as pwquality:
            result_tmp = re.sub(".*password.*sufficient.*pam_unix.so.*" , "\npassword sufficient pam_unix.so sha512 shadow try_first_pass use_authtok\n" , result_tmp)
            pwquality.write(result_tmp)
            pwquality.close()
        with open ("/etc/authselect/custom/custom-profile/system-auth" , "rt" , buffering = 1 ) as pwquality:
            result_tmp = pwquality.read()
            pwquality = pwquality.close()
        with open ("/etc/authselect/custom/custom-profile/system-auth" , "wt" , buffering = 1 ) as pwquality:
            result_tmp = re.sub(".*password.*sufficient.*pam_unix.so.*" , "\npassword sufficient pam_unix.so sha512 shadow try_first_pass use_authtok remember=5\n" , result_tmp)
            pwquality.write(result_tmp)
            pwquality.close()
        
        cmd = "authselect apply-changes"
        cmd = cmd.split()
        with subprocess.Popen(cmd, stdout = step5) as apply:
            stdout,stderr = apply.communicate()
        
        step5.write("# 5.5.1.1 Ensure password expiration is 365 days or less\n")
        with open ("/etc/login.defs" , "rt" , buffering = 1 ) as pwquality:
            result_tmp = pwquality.read()
            pwquality = pwquality.close()
        with open ("/etc/login.defs" , "wt" , buffering = 1 ) as pwquality:
            result_tmp = re.sub(".*PASS_MAX_DAYS.*" , "" , result_tmp)
            pwquality.write(result_tmp)
            pwquality.write("\nPASS_MAX_DAYS 365\n")
            pwquality.close()
        
        step5.write("# 5.5.1.2 Ensure minimum days between password changes is 7 or more\n")
        with open ("/etc/login.defs" , "rt" , buffering = 1 ) as pwquality:
            result_tmp = pwquality.read()
            pwquality = pwquality.close()
        with open ("/etc/login.defs" , "wt" , buffering = 1 ) as pwquality:
            result_tmp = re.sub(".*PASS_MIN_DAYS.*" , "" , result_tmp)
            pwquality.write(result_tmp)
            pwquality.write("\nPASS_MIN_DAYS 7\n")
            pwquality.close()

        with subprocess.Popen(['/bin/sh', '-c' , 'grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1' ] , stdout = subprocess.PIPE, stderr = subprocess.STDOUT) as process:
            stdout , stderr = process.communicate()
            result = stdout.decode('utf-8')
            result = result.split()
        for line in result:
            with subprocess.Popen(['/bin/sh' , '-c' , f"chage --mindays 7 {line}" ] , stdout = subprocess.PIPE ) as temp:
                stdout , stderr = temp.communicate()
            with subprocess.Popen(['/bin/sh' , '-c' , f"chage --maxdays 365 {line}" ] , stdout = subprocess.PIPE ) as temp:
                stdout , stderr = temp.communicate()
        
        step5.write("# 5.5.1.3 Ensure password expiration warning days is 7 or more\n")
        with open ("/etc/login.defs" , "rt" , buffering = 1 ) as pwquality:
            result_tmp = pwquality.read()
            pwquality = pwquality.close()
        with open ("/etc/login.defs" , "wt" , buffering = 1 ) as pwquality:
            result_tmp = re.sub(".*PASS_WARN_AGE.*" , "" , result_tmp)
            pwquality.write(result_tmp)
            pwquality.write("PASS_WARN_AGE 7")
            pwquality.close()
        with subprocess.Popen(['/bin/sh', '-c' , 'grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1' ] , stdout = subprocess.PIPE, stderr = subprocess.STDOUT) as process:
            stdout , stderr = process.communicate()
            result = stdout.decode('utf-8')
            result = result.split()
        for line in result:
            with subprocess.Popen(['/bin/sh' , '-c' , f"chage --warndays 7 {line}" ] , stdout = subprocess.PIPE ) as temp:
                stdout , stderr = temp.communicate()

        step5.write("# 5.5.1.4 Ensure inactive password lock is 30 days or less\n")
        with subprocess.Popen(['/bin/sh' , '-c' , 'useradd -D -f 30' ] , stdout = subprocess.PIPE ) as temp:
                stdout , stderr = temp.communicate()

        with subprocess.Popen(['/bin/sh', '-c' , 'grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1' ] , stdout = subprocess.PIPE, stderr = subprocess.STDOUT) as process:
            stdout , stderr = process.communicate()
            result = stdout.decode('utf-8')
            result = result.split()
        for line in result:
            with subprocess.Popen(['/bin/sh' , '-c' , f"chage --inactive 30 {line}" ] , stdout = subprocess.PIPE ) as temp:
                stdout , stderr = temp.communicate()
        
        step5.write("# 5.5.3 Ensure default user shell timeout is 900 seconds or less\n")
        with open("/etc/bashrc" , "rt" , buffering = 1) as tmp_user:
            result_tmp = tmp_user.read()
            tmp_user.close()
        with open("/etc/bashrc" , "wt" , buffering = 1) as tmp_user:
            tmp_user.write(result_tmp)
            tmp_user.write("\nreadonly TMOUT=900 ; export TMOUT\n")
            tmp_user.close()
        
        with open("/etc/profile" , "rt" , buffering = 1) as tmp_user:
            result_tmp = tmp_user.read()
            tmp_user.close()
        with open("/etc/profile" , "wt" , buffering = 1) as tmp_user:
            tmp_user.write(result_tmp)
            tmp_user.write("\nreadonly TMOUT=900 ; export TMOUT\n")
            tmp_user.close()

        step5.write("# 5.5.4 Ensure default group for the root account is GID 0\n")
        cmd = "usermod -g 0 root"
        cmd = cmd.split()
        with subprocess.Popen(cmd , stdout = step5) as tmp:
            stdout,stderr = tmp.communicate()

        step5.write("# 5.5.5 Ensure default user umask is 027 or more restrictive\n")
        with open("/etc/bashrc" , "rt" , buffering = 1) as tmp_user:
            result_tmp = tmp_user.read()
            tmp_user.close()
        with open("/etc/bashrc" , "wt" , buffering = 1) as tmp_user:
            result_tmp = re.sub ("umask 022" , "umask 027" , result_tmp)
            tmp_user.write(result_tmp)
            tmp_user.close()
        
        with open("/etc/profile" , "rt" , buffering = 1) as tmp_user:
            result_tmp = tmp_user.read()
            tmp_user.close()
        with open("/etc/profile" , "wt" , buffering = 1) as tmp_user:
            result_tmp = re.sub ("umask 022" , "umask 027" , result_tmp)
            tmp_user.write(result_tmp)
            tmp_user.close()
        
def step6():
    with open("/root/0dev.log" , "a+" , buffering = 1) as step6:
        step6.write("# 6.1.2 Ensure permissions on /etc/passwd are configured properly\n")
        cmd = "chown root:root /etc/passwd"
        cmd2 = "chmod 644 /etc/passwd"
        cmd = cmd.split()
        cmd2 = cmd2.split()
        with subprocess.Popen(cmd , stdout = step6 ) as tmp01:
            stdout,stderr = tmp01.communicate()
        with subprocess.Popen(cmd2 , stdout = step6 ) as tmp02:
            stdout,stderr = tmp02.communicate()

        step6.write("# 6.1.3 Ensure permissions on /etc/shadow are configured properly\n")
        cmd = "chown root:root /etc/shadow"
        cmd2 = "chmod o-rwx,g-wx /etc/shadow"
        cmd = cmd.split()
        cmd2 = cmd2.split()
        
        with subprocess.Popen (cmd , stdout = step6) as tmp03:
            stderr,stdout = tmp03.communicate()
        with subprocess.Popen (cmd2 , stdout = step6) as tmp04:
            stderr,stdout = tmp04.communicate()
       
        
        step6.write("# 6.1.4 Ensure permissions on /etc/group are configured properly\n")
        cmd = "chown root:root /etc/group"
        cmd2 = "chmod 644 /etc/group"
        cmd = cmd.split()
        cmd2 = cmd2.split()
        with subprocess.Popen (cmd , stdout = step6) as tmp06:
            stderr,stdout = tmp06.communicate()
        with subprocess.Popen (cmd2 , stdout = step6) as tmp07:
            stderr,stdout = tmp07.communicate()
        
        step6.write("# 6.1.5 Ensure permissions on /etc/gshadow are configured properly\n")
        cmd = "chown root:root /etc/gshadow"
        cmd2 = "chmod o-rwx,g-wx /etc/shadow"
        cmd = cmd.split()
        cmd2 = cmd2.split()
        with subprocess.Popen (cmd , stdout = step6) as tmp08:
            stderr,stdout = tmp08.communicate()
        with subprocess.Popen (cmd2 , stdout = step6) as tmp09:
            stderr,stdout = tmp09.communicate()
        
        step6.write("# 6.1.6 Ensure permissions on /etc/passwd- are configured properly\n")
        cmd = "chown root:root /etc/passwd-"
        cmd2 = "chmod u-x,go-rwx /etc/passwd-"
        cmd = cmd.split()
        cmd2 = cmd2.split()
        with subprocess.Popen (cmd , stdout = step6) as tmp10:
            stderr,stdout = tmp10.communicate()
        with subprocess.Popen (cmd2 , stdout = step6) as tmp11:
            stderr,stdout = tmp11.communicate()
        
        step6.write("# 6.1.7 Ensure permissions on /etc/shadow- are configured properly\n")
        cmd = " chown root:root /etc/shadow-"
        cmd2 = "chmod u-x,go-rwx /etc/shadow-"
        cmd = cmd.split()
        cmd2 = cmd2.split()
        with subprocess.Popen (cmd , stdout = step6) as tmp12:
            stderr,stdout = tmp12.communicate()
        with subprocess.Popen (cmd2 , stdout = step6) as tmp13:
            stderr,stdout = tmp13.communicate()
        
        step6.write("# 6.1.8 Ensure permissions on /etc/group- are configured properly\n")
        cmd = "chown root:root /etc/group-"
        cmd2 = "chmod u-x,go-wx /etc/group-"
        cmd = cmd.split()
        cmd2 = cmd2.split()
        with subprocess.Popen (cmd , stdout = step6) as tmp14:
            stderr,stdout = tmp14.communicate()
        with subprocess.Popen (cmd2 , stdout = step6) as tmp15:
            stderr,stdout = tmp15.communicate()
        
        step6.write("# 6.1.9 Ensure permissions on /etc/gshadow- are configured properly\n")
        cmd = "chown root:root /etc/gshadow-"
        cmd2 = "chmod o-rwx,g-rw /etc/gshadow-"
        cmd = cmd.split()
        cmd2 = cmd2.split()
        with subprocess.Popen (cmd , stdout = step6) as tmp16:
            stderr,stdout = tmp16.communicate()
        with subprocess.Popen (cmd2 , stdout = step6) as tmp17:
            stderr,stdout = tmp17.communicate()

        
        
        

        


# Call the main() function to start script processing. ENJOY
main()


