### Information Reaper


Information Reaper is an information gathering tool designed to collect WHOIS data, DNS records, geolocation information, and perform Shodan searches for a given domain or IP address. This script helps in footprinting and reconnaissance tasks for security assessments.

## Features
- WHOIS data retrieval
- DNS record lookup (A, NS, MX, TXT)
- Geolocation information
- Shodan search for IPs and terms

## Requirements
- Python 3.x
- Required Python libraries:
  - `whois`
  - `dns.resolver`
  - `shodan`
  - `requests`
  - `argparse`
  - `socket`
  - `re`
  - `colorama`

You can install the required libraries using pip:
```
pip install python-whois dnspython shodan requests argparse colorama
```

## Usage
```
python3 information_reaper.py -d DOMAIN [-s IP] [-o OUTPUT]
```

### Options
- `-d`, `--domain` : Specify the domain name for footprinting.
- `-s`, `--shodan` : Provide an IP address or search terms (e.g., 'win7, SMB, wordpress, apache') for Shodan search.
- `-o`, `--output` : Specify a file name to save the output.

### Example
```
python3 information_reaper.py -d example.com -s 8.8.8.8 -o results.txt
```

## Output
The script outputs the results of WHOIS data, DNS records, geolocation information to the console. If the `-o` option is used, the output is saved to the specified file.

## Script Details
The script includes several modules:

1. **WHOIS Module**: Retrieves WHOIS information for the specified domain.
2. **DNS Module**: Fetches A, NS, MX, and TXT records for the specified domain.
3. **Geolocation Module**: Retrieves geolocation information for the domain's IP address.
4. **Shodan Module**: Performs a Shodan search for the given IP address or search terms.

## Script Flowchart
![Alt Text](https://github.com/omershaik0/Information_Reaper/blob/main/information_reaper_flowchart.png)

## In Action
![Alt Text](https://github.com/omershaik0/Information_Reaper/blob/main/Information_Reaper.gif)

## Disclaimer
* Use ethically :)
