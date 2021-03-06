# FollinaReg

![](img.png)

This is a simple python script to automate collection of artifacts for Follina (CVE-2022-30190) exploit on Windows workstations.
The script expects a list of computers and checks registry keys for each user on each computer on the list.
Each domain is scanned using VirusTotal API.
The results (URLs and VirusTotal scans) are stored in a file.

## How to install

```
git clone https://github.com/VirtualSamuraii/FollinaReg.git
cd FollinaReg
pip install -r requirements.txt
```

## How to use

Create accounts on VirusTotal and get yourself an API key.

Put your API key in the conf.cfg file.

Create a text file containing a computer name (e.g \\\\DESKTOP-8SG7NX) on each line.

And run the script with :

```
python FollinaReg.py -l YOUR_COMPUTERS_LIST_FILE.txt
```

## Troubleshooting

Please make sure that you have a valid UNC name, have permissions on remote hosts, and have not been blocked by a firewall.

## Reminder

- Do not rely your investigation process on this script since APTs can cover their tracks simply by deleting artifacts in the Windows registry.
- Do not rely your analysis based on VirusTotal or urlscan since APTs can use legitimate domains or IPs to hide their actions.
