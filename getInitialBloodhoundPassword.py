import docker
import subprocess
import os 
import sys

def check_root():
    if os.getuid() !=0:
        print("Please run the script as root (using sudo).")
        sys.exit(1)

def get_container_id_by_image(image_name):
    # Connect to the Docker daemon
    client = docker.from_env()

    # Get a list of all containers, including stopped ones
    all_containers = client.containers.list(all=True)

    # Search for the container with the specified image
    for container in all_containers:
        if image_name in container.image.tags:
            return container.id

    return None

def get_container_logs(container_id, search_string, output_file):
    # Connect to the Docker daemon
    client = docker.from_env()

    # Get the container object
    container = client.containers.get(container_id)

    # Print only the 6th column of lines that contain the specified search string
    print(f"Logs for Container {container.name} ({container.short_id}):")
    
    try:
        # Get the logs for the container
        logs = container.logs().decode("utf-8")
        
        # Use awk to print the 6th column of lines containing the search string and write to a file
        command = f"echo '{logs}' | awk '/{search_string}/{{print $6}}' > {output_file}"
        subprocess.run(command, shell=True)
        
        print(f"Output written to {output_file}")
        
    except docker.errors.APIError as e:
        print(f"Error retrieving logs for {container.name} ({container.short_id}): {e}")

if __name__ == "__main__":
    check_root()
    
    # Specify the image name for the container you want to find
    
    target_image = "specterops/bloodhound:latest"
    
    # Get the container ID for the specified image
    container_id = get_container_id_by_image(target_image)

    if container_id:
        # If the container is found, get and print the 6th column of lines with the specified content
        search_string = "Initial Password Set To:"
        output_file = "bloodhound-password.txt"
        get_container_logs(container_id, search_string, output_file)
    else:
        print(f"No running container found with the image: {target_image}")
