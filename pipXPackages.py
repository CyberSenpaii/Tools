import os
import subprocess
import sys

def check_root():
    # Check if the script is run as root
    if os.geteuid() == 0:
        print('Please do not run this script as root (using sudo).')
        sys.exit(1)

def install_pipx_and_packages():
    # Construct the apt install command

	setupPipx = 'python3 -m pip install --user pipx && python3 -m pipx ensurepath --force'
	installAutoRecon = 'pipx install git+https://github.com/Tib3rius/AutoRecon.git'
	installFierce = 'pipx install fierce --force'
  
	try:
	# Run the command using subprocesssubprocess.run(setupLinWinPwn, shell=True, check=True)
		subprocess.run(setupPipx, shell=True, check=True)
		subprocess.run(installFierce, shell=True, check=True)
		subprocess.run(installAutoRecon, shell=True, check=True)
		print(f'Successfully installed pipx packages')
	except subprocess.CalledProcessError as e:
        	print(f'Error installing packages: {e}')


if __name__ == "__main__":
	check_root()
	install_pipx_and_packages()
