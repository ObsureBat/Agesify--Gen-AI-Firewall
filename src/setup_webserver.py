import boto3
import paramiko
import time
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_victim_instance():
    """Get the victim instance details"""
    ec2 = boto3.client('ec2')
    response = ec2.describe_instances(
        Filters=[
            {'Name': 'instance-state-name', 'Values': ['running']},
            {'Name': 'tag:Name', 'Values': ['Victim-Server']}
        ]
    )
    
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            return {
                'id': instance['InstanceId'],
                'public_ip': instance['PublicIpAddress'],
                'key_name': instance['KeyName']
            }
    
    raise Exception("Could not find victim instance")

def setup_webserver(instance_details, key_path):
    """Set up a basic web server on the victim instance"""
    try:
        # Verify key file exists and has correct permissions
        if not os.path.exists(key_path):
            raise Exception(f"Key file not found: {key_path}")
        
        logging.info(f"Using key file: {key_path}")
        
        # Connect to instance
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Wait for instance to be ready
        logging.info(f"Waiting for instance {instance_details['public_ip']} to be ready...")
        time.sleep(60)  # Wait for instance initialization
        
        # Try different usernames
        usernames = ['ubuntu', 'ec2-user']
        connected = False
        
        for username in usernames:
            try:
                logging.info(f"Attempting to connect as {username}...")
                ssh.connect(
                    instance_details['public_ip'],
                    username=username,
                    key_filename=key_path,
                    timeout=30
                )
                logging.info(f"Successfully connected as {username}")
                connected = True
                break
            except Exception as e:
                logging.warning(f"Failed to connect as {username}: {str(e)}")
        
        if not connected:
            raise Exception("Failed to connect with any username")
        
        # Install and start Apache
        commands = [
            # Check which package manager to use
            'if command -v apt-get > /dev/null; then\n'
            '  sudo apt-get update -y\n'
            '  sudo apt-get install -y apache2\n'
            '  sudo systemctl start apache2\n'
            '  sudo systemctl enable apache2\n'
            '  WEBROOT=/var/www/html\n'
            'else\n'
            '  sudo yum update -y\n'
            '  sudo yum install -y httpd\n'
            '  sudo systemctl start httpd\n'
            '  sudo systemctl enable httpd\n'
            '  WEBROOT=/var/www/html\n'
            'fi',
            'echo "<html><body><h1>Test Server</h1><p>This is a test web server for WAF testing.</p></body></html>" | sudo tee $WEBROOT/index.html',
            'sudo chmod 644 $WEBROOT/index.html',
            'if command -v apache2 > /dev/null; then\n'
            '  sudo systemctl status apache2\n'
            'else\n'
            '  sudo systemctl status httpd\n'
            'fi'
        ]
        
        for cmd in commands:
            logging.info(f"Running: {cmd}")
            stdin, stdout, stderr = ssh.exec_command(cmd)
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status != 0:
                error = stderr.read().decode()
                logging.error(f"Command failed with status {exit_status}: {error}")
            else:
                output = stdout.read().decode()
                logging.info(f"Command output: {output}")
        
        logging.info("Web server setup completed successfully")
        
    except Exception as e:
        logging.error(f"Error setting up web server: {str(e)}")
        raise
    finally:
        if 'ssh' in locals():
            ssh.close()

def main():
    try:
        # Get victim instance details
        instance_details = get_victim_instance()
        logging.info(f"Found victim instance: {instance_details['id']}")
        
        # Get the key path from the user
        key_path = input("Enter the path to your EC2 key pair file (.pem): ").strip()
        
        # Set up the web server
        setup_webserver(instance_details, key_path)
        
        print("\nNext steps:")
        print(f"1. Test the web server: http://{instance_details['public_ip']}")
        print("2. Run the attack simulation script")
        print("3. Monitor the WAF and CloudWatch metrics")
        
    except Exception as e:
        logging.error(f"Setup failed: {str(e)}")
        raise

if __name__ == '__main__':
    main() 