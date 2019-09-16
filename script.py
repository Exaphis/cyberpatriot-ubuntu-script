import subprocess, os, time, sys, json, grp, pwd


def print_difference(set1, set1name, set2, set2name):
    print("{} - {}: {}".format(set1name, set2name, ", ".join(set1 - set2)))
    print("{} - {}: {}".format(set2name, set1name, ", ".join(set2 - set1)))


def get_file(filepath):
    with open(filepath, "r") as f:
        out = f.read().splitlines()
    return out


def get_output(command, outfile=None):
    if outfile is None:
        c = command
    else:
        c = "{} | tee {}".format(command, outfile)

    command_out = subprocess.Popen(c,
     shell=True,
     stdout=subprocess.PIPE,
     executable="/bin/bash")
    return command_out.stdout.read().decode().splitlines()


if "CyberPatriot" not in os.getcwd():
    print("Please run the script from the CyberPatriot directory.")
    exit()
if os.geteuid() != 0:
    print("Please run the script as root.")
    exit()

input("Are the forensics questions solved?")
print("---------")
input("Are Firefox settings correctly set?")
print("---------")
input("Please fill out information in the allowed directory.")
print("---------")
input("Check /etc/sudoers")
print("---------")

# Get /etc/passwd info
passwd = get_file("/etc/passwd")
current_users = []
for line in passwd:
    user, encrypted_pass, uid, gid, info, home_dir, shell = line.split(":")
    current_users.append({"user": user, "encrypted_pass": encrypted_pass, "uid": uid,
    "gid": gid, "info": info, "home_dir": home_dir, "shell": shell})

# Get allowed users/admins/packages
allowed_users = set(get_file("allowed/allowed_users.txt"))
allowed_admins = set(get_file("allowed/allowed_admins.txt"))
allowed_packages = set(x for x in get_file("allowed/allowed_packages.txt") if len(x) > 0 and x[0] != "#")

# Get all default values
default_users = set(get_file("defaults/default_users.txt"))
default_groups = set(get_file("defaults/default_groups.txt"))
default_packages = set(get_file("defaults/default_packages.txt"))

total_users = default_users | allowed_users
total_groups = default_groups | allowed_users

# Get Ubuntu information
codename = get_output("lsb_release -c -s")[0]

# Difference between allowed users and existing users
users = set(get_output("compgen -u", outfile="out/users.txt"))
print_difference(users, "current users", total_users, "allowed users")
print("---------")

# Difference between allowed groups and existing groups
groups = set(get_output("compgen -g", outfile="out/groups.txt"))
print_difference(groups, "current groups", total_groups, "allowed groups")
print("---------")

# Difference between allowed admins and existing sudoers
sudoers = set(get_output("getent group sudo | cut -d: -f4", outfile="out/sudoers.txt")[0].split(","))
print_difference(sudoers, "current sudoers", allowed_admins, "allowed admins")
print("---------")

# Difference between default installed packages and newly installed packages
# packages = set(get_output("apt-mark showmanual", outfile="out/packages.txt"))
# print_difference(packages, "current packages", default_packages, "default packages")
# print("---------")

# Add new admin user
subprocess.call(["sudo", "adduser", "parktudor"])
proc = subprocess.Popen(["sudo", "passwd", user], 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE)
proc.stdin.write("GreatYear2019!@\n".encode("ascii"))
proc.stdin.write("GreatYear2019!@\n".encode("ascii"))
proc.stdin.flush()
subprocess.call(["sudo", "usermod", "-aG", "sudo", "parktudor"])

# Find uid=0 users
if input("Find UID/GID=0 users? (y/n) ") == "y":
    uid0 = [x for x in current_users if (x["uid"] == "0" or x["gid"] == "0") and x["user"] != "root"]
    if len(uid0) > 0:
        print("WARNING: UID/GID=0 USERS FOUND")
        print(json.dumps(uid0, indent=4))
        input()
    else:
        print("No UID/GID=0 users found")
print("---------")

# Reset rc.local file
if input("Reset /etc/rc.local? (y/n) ") == "y":
    subprocess.call(["sudo", "cp", "-n", "/etc/rc.local", "backup/rc.local"])
    with open("/etc/rc.local", "w") as conf:
        conf.write("\n".join(get_file("defaults/default_rc.local")))
print("---------")

# Reset sources.list
# https://askubuntu.com/questions/586595/restore-default-apt-repositories-in-sources-list-from-command-line/586606
if input("Reset sources.list? (y/n) ") == "y":
    subprocess.call(["sudo", "cp", "-n", "/etc/apt/sources.list", "backup/sources.list"])
    with open("/etc/apt/sources.list", "w") as conf:
        conf.write("deb http://archive.ubuntu.com/ubuntu " + codename + " main multiverse universe restricted\n")
        conf.write("deb http://archive.ubuntu.com/ubuntu " + codename + "-security main multiverse universe restricted")
    subprocess.call(["sudo", "apt", "update"])
print("---------")

# Ask user to enable automatic updates
input("Please enable automatic updates.")
print("---------")

# Change all users' passwords (not admins)
only_users = allowed_users - allowed_admins

print("allowed users: {}".format(only_users))
if input("Change all allowed users passwords? (y/n) ") == "y":
    for user in only_users:
        proc = subprocess.Popen(["sudo", "passwd", user], 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE)
        proc.stdin.write("Cyberpatriot1!\n".encode("ascii"))
        proc.stdin.write("Cyberpatriot1!\n".encode("ascii"))
        proc.stdin.flush()
        print("Changed password of user {}".format(user))
        time.sleep(1)
print("---------")

# OpenSSH
if "openssh" in allowed_packages:
    print("OpenSSH")
    subprocess.call(["sudo", "apt", "install", "openssh-server", "-y"])

    # PermitRootLogin no
    if input("Reset /ssh/sshd_cofig? (y/n) ") == "y":
        subprocess.call(["sudo", "service", "sshd", "stop"])
        subprocess.call(["sudo", "cp", "-n", "/etc/ssh/sshd_config", "backup/sshd_config"])
        with open("/etc/ssh/sshd_config", "w") as conf:
            conf.write("\n".join(get_file("defaults/default_sshd_config")))
        subprocess.call(["sudo", "service", "sshd", "start"])
print("---------")

# Secure sysctl
# TODO: https://hastebin.com/amatifuwan.coffeescript
# https://pastebin.com/SyKKvXWX
if input("Secure sysctl? (y/n) ") == "y":
    subprocess.call(["sudo", "cp", "-n", "/etc/sysctl.conf", "backup/sysctl.conf"])
    with open("/etc/sysctl.conf", "w") as conf:
        conf.write("\n".join(get_file("defaults/default_sysctl.conf")))
    subprocess.call(["sudo", "sysctl", "-p"])
print("---------")

# Enable firewall
if input("Enable firewall? (y/n) ") == "y":
    subprocess.call(["sudo", "ufw", "enable"])
    subprocess.call(["sudo", "ufw", "deny", "23"])
    subprocess.call(["sudo", "ufw", "deny", "2049"])
    subprocess.call(["sudo", "ufw", "deny", "515"])
    subprocess.call(["sudo", "ufw", "deny", "111"])
print("---------")

# Disable guest login and automatic login
if input("Disable guest/automatic login? (y/n) ") == "y":
    with open("/etc/lightdm/lightdm.conf", "w") as conf:
        conf.write("[SeatDefaults]\nallow-guest=false\n")
print("---------")

# Change root password to Cyberpatriot1!
if input("Change root password? (y/n) ") == "y":
    proc = subprocess.Popen(["sudo", "passwd"], 
        stdin=subprocess.PIPE, 
        stdout=subprocess.PIPE)
    proc.stdin.write("Cyberpatriot1!\n".encode("ascii"))
    proc.stdin.write("Cyberpatriot1!\n".encode("ascii"))
    proc.stdin.flush()
    time.sleep(1)
print("---------")

# Disable root login
if input("Disable root login? (y/n) ") == "y":
    subprocess.call(["sudo", "passwd", "-dl", "root"])
print("---------")

# Password policy
if input("Enable password policy? (y/n) ") == "y":
    # Install libpam-cracklib
    subprocess.call(["sudo", "apt-get", "install", "libpam-cracklib"])

    # Set /etc/pam.d/common-password
    lines = []
    cracklib_exists = False
    script_ran = False
    with open("/etc/pam.d/common-password", "r") as conf:
        for line in conf.read().splitlines():
            if "pam_unix.so" in line:
                lines.append(line + " minlen=8 remember=5")
            elif "pam_cracklib.so" in line:
                cracklib_exists = True
                lines.append(line + " ucredit=-1 lcredit=-2 dcredit=-1 ocredit=-1")
            elif "Script" in line:
                script_ran = True
            else:
                lines.append(line)

    if not script_ran:
        if not cracklib_exists:
            lines.append("")
            lines.append("# libpam-cracklib")
            lines.append("password        requisite                       pam_cracklib.so retry=3 minlen=14 difok=3 ucredit=-1 lcredit=-2 dcredit=-1 ocredit=-1")
        lines.append("\n# Script ran.")
        subprocess.call(["sudo", "cp", "-n", "/etc/pam.d/common-password", "backup/common-password"])

        with open("/etc/pam.d/common-password", "w") as conf:
            conf.write("\n".join(lines))
        print("common-password")
    else:
        print("common-password password policy exists.")

    # Set /etc/login.defs
    lines = []
    script_ran = False
    with open("/etc/login.defs", "r") as conf:
        for line in conf.read().splitlines():
            if "#" not in line:
                if "PASS_MAX_DAYS" in line:
                    lines.append("PASS_MAX_DAYS   30")
                elif "PASS_MIN_DAYS" in line:
                    lines.append("PASS_MIN_DAYS   10")
                elif "PASS_WARN_AGE" in line:
                    lines.append("PASS_WARN_AGE   7")
                else:
                    lines.append(line)
            elif "Script" in line:
                script_ran = True
            else:
                lines.append(line)

    if not script_ran:
        lines.append("\n# Script ran.")
        subprocess.call(["sudo", "cp", "-n", "/etc/login.defs", "backup/login.defs"])
        with open("/etc/login.defs", "w") as conf:
            conf.write("\n".join(lines))
        print("login.defs password policy set.")
    else:
        print("login.defs password policy exists.")

    # Set /etc/pam.d/common-auth
    with open("/etc/pam.d/common-auth", "r") as conf:
        lines = conf.read().splitlines()
    if "# Script ran." in lines:
        print("common-auth login policy exists.")
    else:
        subprocess.call(["sudo", "cp", "-n", "/etc/pam.d/common-auth", "backup/common-auth"])
        with open("/etc/pam.d/common-auth", "a") as conf:
            conf.write("\nauth required pam_tally2.so deny=5 onerr=fail unlock_time=300")
            conf.write("\n# Script ran.\n")
        print("common-auth login policy set.")
print("---------")

# Media files
if input("View media files? (y/n) ") == "y":
    media_files = get_output("sudo find / -type f -iname *.mp3", outfile="out/mp3_log.txt")
    print("\n".join(media_files), "\nlength: {}".format(len(media_files)))
    if input("Delete all? (y/n) ") == "y":
        for f in media_files:
            os.remove(f)
print("---------")

# Change crucial file permissions
file_perms = {"/etc/passwd": ("644", "root", "root"),
              "/etc/shadow": ("640", "root", "shadow")}
if input("Change crucial file permissions and ownership? (y/n) ") == "y":
    for file, (correct_perm, correct_user, correct_group) in file_perms.items():
        correct_uid, correct_gid = pwd.getpwnam(correct_user).pw_uid, grp.getgrnam(correct_group).gr_gid
        st = os.stat(file)
        if st.st_uid != correct_uid or st.st_gid != correct_gid:
            print("WARNING: " + file + " owned by " + pwd.getpwuid(st.st_uid).pw_name + ":" + grp.getgrgid(st.st_gid).gr_name)
            if input("Fix? (y/n) ") == "y":
                os.chown(file, correct_uid, correct_gid)

        file_perm = oct(st.st_mode)[-3:]
        if file_perm != correct_perm:
            print("WARNING: " + file + " has incorrect permissions of " + file_perm)
            if input("Fix? (y/n) ") == "y":
                os.chmod(file, int(correct_perm, 8))
print("---------")

# View open files that are using network
if input("View open files that are using network? (y/n) ") == "y":
    subprocess.call(["lsof", "-i", "-n", "-P"])
print("---------")

# Remove known bad programs
bad_programs = ["zenmap", "nmap", "telnet", "hydra", "john", "nitko", "freeciv", "ophcrack", "kismet", "minetest"]
if input("Remove known bad programs? (y/n) ") == "y":
    for program in bad_programs:
        subprocess.call(["sudo", "apt", "purge", program + "*", "-y"])
print("---------")

# List all cronjobs
if input("List all cronjobs? (y/n) ") == "y":
    subprocess.call(["sudo", "./crontab.sh"])
print("---------")

# Secure shared memory
if input("Secure shared memory? (y/n)"):
    with open("/etc/fstab", "a+") as fstab:
        fstab_lines = fstab.read().splitlines()
        if "# Script ran" not in fstab_lines:
            fstab.write("\n# Script ran\nnone     /run/shm     tmpfs     rw,noexec,nosuid,nodev     0     0")
            print("Shared memory secured.")
        else:
            print("Shared memory already secured.")
print("---------")

# Updates
if input("Run updates? (y/n) ") == "y":
    subprocess.call(["sudo", "apt-get", "update"])
    subprocess.call(["spd-say", "\"update has finished\""])
    print("---------")
    time.sleep(1)

    subprocess.call(["sudo", "apt-get", "upgrade", "-y"])
    subprocess.call(["spd-say", "\"upgrade has finished\""])
    print("---------")
    time.sleep(1)

    subprocess.call(["sudo", "apt-get", "dist-upgrade", "-y"])
    subprocess.call(["spd-say", "\"dist-upgrade has finished\""])
    print("---------")
    time.sleep(1)
