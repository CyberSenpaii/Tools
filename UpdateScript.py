import os
import subprocess
import sys

#If you want to add yourself to the docker group to use docker without sudo, an additional step is needed:
#sudo usermod -aG docker $USER

def check_root():
    # Check if the script is run as root
    if os.geteuid() != 0:
        print('Please run the script as root (using sudo).')
        sys.exit(1)

def install_packages(package_list):
    # Convert the list of packages to a space-separated string
    packages_str = ' '.join(package_list)

    # Construct the apt install command
    updateRepos = f'sudo apt update -y'
    command = f'sudo apt install {packages_str} -y'
    upgradeRepos = f'sudo apt upgrade -y'

    try:
        # Run the command using subprocess
        subprocess.run(updateRepos, shell=True, check=True)
        subprocess.run(command, shell=True, check=True)
        subprocess.run(updateRepos, shell=True, check=True)
        subprocess.run(upgradeRepos, shell=True, check=True)
        print(f'Successfully installed packages: {packages_str}')
    except subprocess.CalledProcessError as e:
        print(f'Error installing packages: {e}')

def install_configure_docker_and_build_tools():
    # Construct the apt install command
    updateSourcesList = "printf '%s\n' 'deb https://download.docker.com/linux/debian bullseye stable' | sudo tee /etc/apt/sources.list.d/docker-ce.list"
    gpgKeyFile = '/etc/apt/trusted.gpg.d/docker-ce-archive-keyring.gpg'
    curlGPGKey = 'curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/docker-ce-archive-keyring.gpg'
    wineInstall = 'sudo dpkg --add-architecture i386 && sudo apt update && sudo apt install wine32:i386 -y'
    installDocker = 'sudo apt install -y docker-ce docker-ce-cli containerd.io'
    setupBloodhound = 'sudo docker compose up -d'
    setupSliver = 'curl https://sliver.sh/install | sudo bash'
    setupPipx = 'sudo python3 -m pip install --user pipx'
    pipxAddPath = 'sudo python3 -m pipx ensurepath'
    installAutoRecon = 'sudo pipx install git+https://github.com/Tib3rius/AutoRecon.git'
    installFierce = 'sudo pipx install fierce'
    pullCyberChef = 'docker pull binlab/cyberchef'
    
    try:
        # Run the command using subprocess
        subprocess.run(updateSourcesList, shell=True, check=True)
        if not os.path.exists(gpgKeyFile):
            subprocess.run(curlGPGKey, shell=True, check=True)
        subprocess.run(wineInstall, shell=True, check=True)
        subprocess.run(installDocker, shell=True, check=True)
        subprocess.run(setupBloodhound, shell=True, check=True)
        subprocess.run(setupSliver, shell=True, check=True)
        subprocess.run(setupPipx, shell=True, check=True)
        subprocess.run(pipxAddPath, shell=True, check=True)
        subprocess.run(installFierce, shell=True, check=True)
        subprocess.run(pullCyberChef, shell=True, check=True)
        print(f'Successfully installed docker')
    except subprocess.CalledProcessError as e:
        print(f'Error installing packages: {e}')

def install_pip3_packages(package_list):
    # Convert the list of packages to a space-separated string
    packages_str = ' '.join(package_list)

    # Construct the apt install command
    command = f'pip3 install {packages_str}'

    try:
        # Run the command using subprocess
        subprocess.run(command, shell=True, check=True)
        print(f'Successfully installed packages: {packages_str}')
    except subprocess.CalledProcessError as e:
        print(f'Error installing packages: {e}')

def clone_repositories(repo_urls, destination_folder='.'):
    if not os.path.exists(destination_folder):
        os.makedirs(destination_folder)

    for repo_url in repo_urls:
        repo_name = repo_url.split('/')[-1].rstrip('.git')
        repo_path = os.path.join(destination_folder, repo_name)

        if os.path.exists(repo_path):
            print(f"Repository '{repo_name}' already exists. Skipping...")
        else:
            print(f"Cloning repository: {repo_url}")
            subprocess.run(['git', 'clone', repo_url, repo_path])
            print(f"Repository '{repo_name}' cloned successfully.\n")

if __name__ == "__main__":
    check_root()
    # Example array of Git repository URLs
    red_urls = [
        'https://github.com/SpecterOps/BloodHound.git',
        'https://github.com/BishopFox/sliver.git',
        'https://github.com/fortra/impacket.git',
        'https://github.com/redcanaryco/atomic-red-team.git',
        'https://github.com/1N3/Sn1per.git',
        'https://github.com/matthewdunwoody/POSHSPY.git',
        'https://github.com/JlSakuya/Linux-Privilege-Escalation-Exploits.git',
        'https://github.com/ParrotSec/mimikatz.git',
        'https://github.com/GTFOBins/GTFOBins.github.io.git',
        'https://github.com/LOLBAS-Project/LOLBAS.git',
        'https://github.com/WADComs/WADComs.github.io.git',
        'https://github.com/swisskyrepo/PayloadsAllTheThings.git',
        'https://github.com/DigitalInterruption/cookie-monster.git',
        'https://github.com/t3l3machus/hoaxshell.git',
        'https://github.com/mdsecactivebreach/SharpShooter.git',
        'https://github.com/BC-SECURITY/Empire.git',
        'https://github.com/BC-SECURITY/Starkiller.git',
        'https://github.com/samratashok/nishang.git',
        'https://github.com/The-Viper-One/PsMapExec.git',
        'https://github.com/0dayCTF/reverse-shell-generator.git',
        'https://github.com/ropnop/kerbrute.git',
        'https://github.com/shelld3v/JSshell.git',
        'https://github.com/61106960/adPEAS.git',
        'https://github.com/urbanadventurer/username-anarchy.git',
        'https://github.com/AlessandroZ/LaZagne.git',
        'https://github.com/unode/firefox_decrypt.git',
        'https://github.com/DNSCrypt/dnscrypt-proxy.git',
        'https://github.com/r3motecontrol/Ghostpack-CompiledBinaries.git',
        'https://github.com/rstacruz/cheatsheets.git',
        'https://github.com/az7rb/crt.sh.git',
        'https://github.com/digininja/CeWL.git',
        'https://github.com/juliourena/plaintext.git',
        'https://github.com/its-a-feature/Mythic.git',
        'https://github.com/hausec/ADAPE-Script.git',
        'https://github.com/mitre/caldera.git',
        'https://github.com/redcanaryco/invoke-atomicredteam.git',
        'https://github.com/redcanaryco/chain-reactor.git'
        # Add more repository URLs as needed
    ]
  
    blue_urls = [
        'https://github.com/rizinorg/cutter.git',
        'https://github.com/magicsword-io/LOLDrivers.git',
        'https://github.com/OWASP/CheatSheetSeries.git',
        'https://github.com/redcanaryco/surveyor.git'
        # Add more repository URLs as needed
    ]

    # Specify the destination folder where repositories will be cloned
    red_folder = 'Red'
    blue_folder = 'Blue'

    clone_repositories(red_urls, red_folder)
    clone_repositories(blue_urls, blue_folder)
    
    install_configure_docker_and_build_tools()
    
    apt_packages=[
        'onesixtyone',
        'braa',
        'evolution',
        'leafpad',
        'certipy-ad',
        'golang',
        'peass',
        'seclists',
        'curl',
        'dnsrecon',
        'enum4linux',
        'feroxbuster',
        'gobuster',
        'impacket-scripts',
        'nbtscan',
        'nikto',
        'nmap',
        'oscanner',
        'redis-tools',
        'smbclient',
        'smbmap',
        'snmp',
        'sslscan',
        'sipvicious',
        'tnscmd10g',
        'whatweb',
        'wkhtmltopdf',
        'python3',
        'python3-pip',
        'python3-venv',
        'shellter',
        'dnschef',
        'veil',
        'sqlninja',
        'set',
        'npm',
        'dirsearch',
        'odat',
        'autopsy',
        'yara',
        'ghidra',
        'arkime'
    ]
    
    install_packages(apt_packages)

    pip3_packages=[
        'pyftpdlib',
        'uploadserver',
        'docker',
        'defaultcreds-cheat-sheet'
    ]

    install_pip3_packages(pip3_packages)
