import argparse
import logging
import yaml
import json
import os
import sys
from datetime import datetime
from dateutil.parser import parse as date_parse
try:
    import pwnedpasswords as pwned
except ImportError:
    print("Error: pwnedpasswords library not found. Please install it using: pip install pwnedpasswords")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define default weak password list (expand as needed)
DEFAULT_WEAK_PASSWORDS = ["password", "123456", "qwerty", "admin", "default", "123456789"]

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Checks user accounts for weak or default passwords.")
    parser.add_argument("-u", "--userfile", help="Path to a file containing a list of usernames (one per line).", required=False)
    parser.add_argument("-p", "--passwordfile", help="Path to a file containing a list of passwords (one per line).", required=False)
    parser.add_argument("-c", "--configfile", help="Path to a YAML configuration file with user and password information.", required=False)
    parser.add_argument("-w", "--weakpasswords", help="Path to a file containing a list of weak passwords. Defaults to a built-in list.", required=False)
    parser.add_argument("-t", "--threshold", type=int, default=10, help="Threshold for pwnedpasswords check. If a password has been pwned more than this many times, flag it. Default: 10")
    parser.add_argument("--disable-pwned", action="store_true", help="Disable checking against the pwnedpasswords database.")
    parser.add_argument("--disable-date", action="store_true", help="Disable date-based password detection.")
    parser.add_argument("--disable-common", action="store_true", help="Disable checking against common password list.")
    return parser.parse_args()

def load_users_passwords(userfile, passwordfile, configfile):
    """
    Loads usernames and passwords from specified files or a configuration file.
    Returns a list of tuples: [(username, password), ...]
    """
    user_pass_list = []

    if configfile:
        try:
            with open(configfile, 'r') as f:
                config = yaml.safe_load(f)
                if not isinstance(config, dict):
                    raise ValueError("Invalid YAML config format: root must be a dictionary")
                for username, password in config.items():
                    if not isinstance(username, str) or not isinstance(password, str):
                         raise ValueError("Invalid YAML config format: keys and values must be strings")
                    user_pass_list.append((username, password))
        except FileNotFoundError:
            logging.error(f"Configuration file not found: {configfile}")
            sys.exit(1)
        except yaml.YAMLError as e:
            logging.error(f"Error parsing YAML configuration file: {e}")
            sys.exit(1)
        except ValueError as e:
            logging.error(f"Error in configuration file format: {e}")
            sys.exit(1)

    elif userfile and passwordfile:
        try:
            with open(userfile, 'r') as uf, open(passwordfile, 'r') as pf:
                users = [line.strip() for line in uf]
                passwords = [line.strip() for line in pf]

                if len(users) != len(passwords):
                    logging.error("User and password files must have the same number of entries.")
                    sys.exit(1)

                user_pass_list = list(zip(users, passwords))
        except FileNotFoundError as e:
            logging.error(f"File not found: {e.filename}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Error reading user and password files: {e}")
            sys.exit(1)

    else:
        logging.error("Please provide a configuration file or both user and password files.")
        sys.exit(1)

    return user_pass_list

def load_weak_passwords(weakpasswords_file):
    """
    Loads weak passwords from a file. If no file is provided, uses the default list.
    """
    if weakpasswords_file:
        try:
            with open(weakpasswords_file, 'r') as f:
                weak_passwords = [line.strip().lower() for line in f]
        except FileNotFoundError:
            logging.error(f"Weak password file not found: {weakpasswords_file}. Using default list.")
            return DEFAULT_WEAK_PASSWORDS
        except Exception as e:
            logging.error(f"Error reading weak password file: {e}. Using default list.")
            return DEFAULT_WEAK_PASSWORDS
    else:
        weak_passwords = DEFAULT_WEAK_PASSWORDS

    return weak_passwords

def check_weak_password(password, weak_passwords):
    """
    Checks if a password is in the list of weak passwords.
    """
    return password.lower() in weak_passwords

def check_pwned_password(password, threshold):
    """
    Checks if a password has been compromised using the pwnedpasswords API.
    """
    try:
        count = pwned.check(password)
        if count >= threshold:
            return count
        return 0
    except pwned.errors.APIError as e:
        logging.error(f"Error checking password against pwnedpasswords: {e}")
        return -1 # Indicate an error
    except Exception as e:
        logging.error(f"Unexpected error during pwnedpasswords check: {e}")
        return -1 # Indicate an error

def check_date_based_password(password):
    """
    Checks if the password looks like a date.
    """
    try:
        date_parse(password, fuzzy=True)
        return True
    except ValueError:
        return False

def main():
    """
    Main function to orchestrate the password checking process.
    """
    args = setup_argparse()

    user_pass_list = load_users_passwords(args.userfile, args.passwordfile, args.configfile)
    weak_passwords = load_weak_passwords(args.weakpasswords)

    for username, password in user_pass_list:
        logging.info(f"Checking password for user: {username}")

        if not args.disable_common and check_weak_password(password, weak_passwords):
            logging.warning(f"User: {username} - Password is a common weak password.")

        if not args.disable_pwned:
            pwned_count = check_pwned_password(password, args.threshold)
            if pwned_count > 0:
                logging.warning(f"User: {username} - Password has been compromised and appears {pwned_count} times in the pwnedpasswords database.")
            elif pwned_count == -1:
                logging.warning(f"User: {username} - Password check against pwnedpasswords failed.")

        if not args.disable_date and check_date_based_password(password):
            logging.warning(f"User: {username} - Password appears to be date-based.")

if __name__ == "__main__":
    main()

# Example Usage:
# 1. Using a configuration file (config.yaml):
#    config.yaml:
#    user1: password123
#    user2: 19900101
#    user3: SecurePassword!
#    python main.py -c config.yaml

# 2. Using separate user and password files:
#    users.txt:
#    user1
#    user2
#    user3
#    passwords.txt:
#    password123
#    19900101
#    SecurePassword!
#    python main.py -u users.txt -p passwords.txt

# 3. Using a custom weak password list:
#    weak_passwords.txt:
#    password
#    123456
#    qwerty
#    python main.py -c config.yaml -w weak_passwords.txt

# 4. Disabling pwnedpasswords check:
#    python main.py -c config.yaml --disable-pwned

# 5. Disabling date check:
#    python main.py -c config.yaml --disable-date

# 6. Disabling common password check:
#    python main.py -c config.yaml --disable-common

# 7. Changing the threshold for pwnedpasswords check
#    python main.py -c config.yaml -t 50