# config-cha-WeakPasswordEnforcer
Checks user accounts for weak or default passwords against a built-in dictionary and common patterns. Employs the `pwnedpasswords` library for checking against compromised password lists and `python-dateutil` for detecting date-based passwords. Reports accounts with potentially vulnerable credentials. - Focused on Automates the process of evaluating system and application configurations against security benchmarks (e.g., CIS). Allows users to define and apply hardening profiles, and provides remediation recommendations.

## Install
`git clone https://github.com/ShadowGuardAI/config-cha-weakpasswordenforcer`

## Usage
`./config-cha-weakpasswordenforcer [params]`

## Parameters
- `-h`: Show help message and exit
- `-u`: No description provided
- `-p`: No description provided
- `-c`: Path to a YAML configuration file with user and password information.
- `-w`: Path to a file containing a list of weak passwords. Defaults to a built-in list.
- `-t`: Threshold for pwnedpasswords check. If a password has been pwned more than this many times, flag it. Default: 10
- `--disable-pwned`: Disable checking against the pwnedpasswords database.
- `--disable-date`: Disable date-based password detection.
- `--disable-common`: Disable checking against common password list.

## License
Copyright (c) ShadowGuardAI
