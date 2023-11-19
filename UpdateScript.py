import os
import subprocess

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
    # Example array of Git repository URLs
    red_urls = [
        'https://github.com/SpecterOps/BloodHound.git',
        'https://github.com/BishopFox/sliver.git',
        'https://github.com/fortra/impacket.git',
        'https://github.com/redcanaryco/atomic-red-team.git',
        'https://github.com/carlospolop/PEASS-ng.git',
        'https://github.com/DominicBreuker/pspy.git',
        'https://github.com/1N3/Sn1per.git',
        'https://github.com/Tib3rius/AutoRecon.git',
        'https://github.com/danielmiessler/SecLists.git',
        'https://github.com/matthewdunwoody/POSHSPY.git',
        'https://github.com/mschwager/fierce.git',
        'https://github.com/ParrotSec/shellter.git',
        'https://github.com/iphelix/dnschef.git',
        'https://github.com/Veil-Framework/Veil.git',
        'https://github.com/xxgrunge/sqlninja.git',
        'https://github.com/jpillora/chisel.git',
        'https://github.com/GhostPack/Certify.git',
        'https://github.com/GhostPack/Rubeus.git',
        'https://github.com/GhostPack/Seatbelt.git',
        'https://github.com/GhostPack/SafetyKatz.git',
        'https://github.com/JlSakuya/Linux-Privilege-Escalation-Exploits.git',
        'https://github.com/BeichenDream/GodPotato.git',
        'https://github.com/ParrotSec/mimikatz.git',
        'https://github.com/itm4n/FullPowers.git',
        'https://github.com/GTFOBins/GTFOBins.github.io.git',
        'https://github.com/LOLBAS-Project/LOLBAS.git',
        'https://github.com/WADComs/WADComs.github.io.git',
        '
        # Add more repository URLs as needed
    ]
  
    blue_urls = [
        'https://github.com/mandiant/flare-floss.git',
        'https://github.com/rizinorg/cutter.git',
        'https://github.com/sleuthkit/autopsy.git',
        'https://github.com/VirusTotal/yara.git',
        'https://github.com/magicsword-io/LOLDrivers.git',
        '
        # Add more repository URLs as needed
    ]

    # Specify the destination folder where repositories will be cloned
    red_folder = 'Red'
    blue_folder = 'Blue'

    clone_repositories(red_urls, red_folder)
    clone_repositories(blue_urls, blue_folder)
