import os
import subprocess
import sys



def check_root():
    # Check if the script is run as root
    if os.geteuid() != 0:
        print('Please run the script as root (using sudo).')
        sys.exit(1)

def updateSudoersFiles():
	sudoers_content = """
	# This file MUST be edited with the 'visudo' command as root.
	#
	# Please consider adding local content in /etc/sudoers.d/ instead of
	# directly modifying this file.
	#
	# See the man page for details on how to write a sudoers file.
	#
	Defaults	env_reset
	Defaults	mail_badpass
	Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.local/bin"

	# This fixes CVE-2005-4890 and possibly breaks some versions of kdesu
	# (#1011624, https://bugs.kde.org/show_bug.cgi?id=452532)
	Defaults	use_pty

	# This preserves proxy settings from user environments of root
	# equivalent users (group sudo)
	#Defaults:%sudo env_keep += "http_proxy https_proxy ftp_proxy all_proxy no_proxy"

	# This allows running arbitrary commands, but so does ALL, and it means
	# different sudoers have their choice of editor respected.
	#Defaults:%sudo env_keep += "EDITOR"

	# Completely harmless preservation of a user preference.
	#Defaults:%sudo env_keep += "GREP_COLOR"

	# While you shouldn't normally run git as root, you need to with etckeeper
	#Defaults:%sudo env_keep += "GIT_AUTHOR_* GIT_COMMITTER_*"

	# Per-user preferences; root won't have sensible values for them.
	#Defaults:%sudo env_keep += "EMAIL DEBEMAIL DEBFULLNAME"

	# "sudo scp" or "sudo rsync" should be able to use your SSH agent.
	#Defaults:%sudo env_keep += "SSH_AGENT_PID SSH_AUTH_SOCK"

	# Ditto for GPG agent
	#Defaults:%sudo env_keep += "GPG_AGENT_INFO"

	# Host alias specification

	# User alias specification

	# Cmnd alias specification

	# User privilege specification
	root	ALL=(ALL:ALL) ALL

	# Allow members of group sudo to execute any command
	%sudo	ALL=(ALL:ALL) ALL

	# See sudoers(5) for more information on "@include" directives:

	@includedir /etc/sudoers.d
	"""

	# Backup the current sudoers file
	sudoers_path = "/etc/sudoers"
	backup_path = "/etc/sudoers.bak"

	try:
		with open(backup_path, 'w') as backup_file:
			with open(sudoers_path, 'r') as sudoers_file:
				backup_file.write(sudoers_file.read())
	except Exception as e:
		print(f"Error creating backup: {e}")
		exit(1)

	# Replace the sudoers file with the new content
	try:
		with open(sudoers_path, 'w') as sudoers_file:
			sudoers_file.write(sudoers_content)
	except Exception as e:
		print(f"Error replacing sudoers file: {e}")
		exit(1)

	print("Sudoers file replaced successfully. Make sure to check for any errors using 'visudo' before exiting.")

def runInstallFiles():
	runSniperInstall = 'sudo bash Red/Sn1per/install.sh'
	runEmpireInstall = 'sudo bash /home/kali/Desktop/Tools/Red/Empire/setup/install.sh'
	runStarKillerInstall = 'sudo npm --prefix Red/Starkiller install'
	runCookieMonsterInstall = 'sudo npm --prefix Red/cookie-monster install'
	compileKerbrute = 'sudo make all --directory Red/kerbrute'
	runMythicInstall = 'sudo make --directory Red/Mythic'
	
	
	try:
		# Run the command using subprocess
		subprocess.run(runSniperInstall, shell=True, check=True)
		subprocess.run(runEmpireInstall, shell=True, check=True)
		subprocess.run(runStarKillerInstall, shell=True, check=True)
		subprocess.run(runCookieMonsterInstall, shell=True, check=True)
		subprocess.run(compileKerbrute, shell=True, check=True)
		subprocess.run(runMythicInstall, shell=True, check=True)
		print(f'Successfully ran install scripts.')
	except subprocess.CalledProcessError as e:
		print(f'Error running install scripts: {e}')

if __name__ == "__main__":
	check_root()
	updateSudoersFiles()
	runInstallFiles()
    # ensure root
