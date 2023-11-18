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
        'https://github.com/SpecterOps/BloodHound.git'
        # Add more repository URLs as needed
    ]
  
    blue_urls = [
        'https://github.com/mandiant/flare-floss.git'
        # Add more repository URLs as needed
    ]

    # Specify the destination folder where repositories will be cloned
    red_folder = 'Red'
    blue_folder = 'Blue'

    clone_repositories(red_urls, red_folder)
    clone_repositories(blue_urls, blue_folder)
