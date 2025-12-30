# tapo-cli: Tapo TP-Link Cloud Video Downloader

tapo-cli is a command-line utility designed to streamline the process of batch-downloading your videos from the Tapo TP-Link Cloud.

Please note that this utility has not been tested on Windows systems. It is recommended to utilize the [Windows Subsystem for Linux (WSL)](https://learn.microsoft.com/en-us/windows/wsl/install) for Windows users.

The utility is compatible with any Debian-based operating system that has `python3` and `pip3` installed.

## Usage Instructions
To begin using Tapo-CLI, follow these steps:

```
git clone https://github.com/dimme/tapo-cli.git

sudo apt update
sudo apt install -y python3-full python3-venv

cd ~/TapoCamera/tapo-cli
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
chmod +x tapo-cli.py

python tapo-cli.py login
python tapo-cli.py list-videos --start 2025-12-01 --end 2025-12-15
python tapo-cli.py download-videos --start 2025-12-01 --end 2025-12-15 --path ~/TapoCamera/videos --overwrite 0
python tapo-cli.py list-devices
python tapo-cli.py list-videos --start 2025-12-29 --end 2025-12-29
```

For additional information and options, please refer to `./tapo-cli.py --help` and `./tapo-cli.py [COMMAND] --help`.

## Automating Backups
### Windows
To automate daily backups on Windows, create a `.bat` file with the following content and schedule it to run once per day using Task Scheduler:

```
ubuntu.exe run "/home/<user>/tapo-cli/tapo-cli.py download-videos --days 7 --path /mnt/c/TapoBackups --overwrite 0"
```

This process requires the [Windows Subsystem for Linux (WSL)](https://learn.microsoft.com/en-us/windows/wsl/install). You may also choose to schedule the task to run upon system logon.

### Linux
To automate daily backups on Linux, create a cron task by executing:

```
sudo crontab -e
```

Then, append a line similar to the one below, adjusted to match your specific paths:

```
30 4 * * *  <user> /home/<user>/tapo-cli/tapo-cli.py download-videos --days 7 --path /home/<user>/TapoBackups --overwrite 0
```

This will schedule the task to run at 4:30 AM every day.
