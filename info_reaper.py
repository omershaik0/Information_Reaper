import sys
import whois
import dns.resolver
import shodan
import requests
import argparse
import socket
import re
from colorama import Fore, Back, Style

# Colors inside variables
r, g, b = 255, 165, 0
def rgb(r, g, b):
    return f'\033[38;2;{r};{g};{b}m'
background = Back.CYAN + Fore.BLACK
magenta = Fore.MAGENTA
green = Fore.GREEN
red = Fore.RED
cyan = Fore.CYAN
blue = Fore.BLUE
yellow = Fore.YELLOW
yellow_bright = rgb(255, 255, 0)
violet = rgb(238, 130, 238)
white = Fore.WHITE
green_bright = rgb(0, 255, 0)
reset = Style.RESET_ALL

print("""
{}
  _____        __                           _   _               _____                            
 |_   _|      / _|                         | | (_)             |  __ \                           
   | |  _ __ | |_ ___  _ __ _ __ ___   __ _| |_ _  ___  _ __   | |__) |___  __ _ _ __   ___ _ __ 
   | | | '_ \|  _/ _ \| '__| '_ ` _ \ / _` | __| |/ _ \| '_ \  |  _  // _ \/ _` | '_ \ / _ \ '__|
  _| |_| | | | || (_) | |  | | | | | | (_| | |_| | (_) | | | | | | \ \  __/ (_| | |_) |  __/ |   
 |_____|_| |_|_| \___/|_|  |_| |_| |_|\__,_|\__|_|\___/|_| |_| |_|  \_\___|\__,_| .__/ \___|_|   
                                                                                | |              
                                                                                |_|              
{}                                        
                                                    {}by unknown_exploit{}                                                
""".format(blue, reset, red, reset))

# Get arguments and parse it using argparse
script_name = sys.argv[0]
arguments = argparse.ArgumentParser(description="This is information gathering tool.", usage=f"python3 {script_name} -d DOMAIN [-s IP]")
arguments.add_argument("-d", "--domain", help="Enter the domain name for footprinting", required=True)
arguments.add_argument("-s", "--shodan", help="Enter the IP or Terms i.e 'win7, SMB, wordpress or apache etc..' for Shodan search", required=False)
arguments.add_argument("-o", "--output", help="Enter the file name to save the script output and to save Shodan output use TEE command", required=False)
args = arguments.parse_args()

# Main variables
domain = args.domain
shodan_search_query = args.shodan
output_file = args.output

#validate if user gave a IP address or a word/term to do shodan search
ip_regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
def ip_check(shodan_search_query):
    if (re.search(ip_regex, shodan_search_query)):
        return "Valid IP address"
    else:
        return "Invalid IP address"

# WHOIS Module
def whois_module():
    if domain:
        global whois_results
        whois_results = ''
        whois_results += "{}[+] Getting WHOIS information for {}{}{}{}".format(background, red, domain, reset, reset)
        print()
        try:
            domain_query = whois.query(domain)
            whois_results += '\n \n'
            whois_results += "{}Name: {}{}".format(yellow_bright, reset, domain_query.name) + '\n'
            whois_results += "{}Registrar: {}{}".format(yellow_bright, reset, domain_query.registrar) + '\n'
            whois_results += "{}Creation Date: {}{}".format(yellow_bright, reset, domain_query.creation_date) + '\n'
            whois_results += "{}Expiration Date: {}{}".format(yellow_bright, reset, domain_query.expiration_date) + '\n'
            whois_results += "{}Registrant: {}{}".format(yellow_bright, reset, domain_query.registrant) + '\n'
            whois_results += "{}Registrant Country: {}{}".format(yellow_bright, reset, domain_query.registrant_country) + '\n'
        except:
            print()
            pass
        print(whois_results)
whois_module()
# DNS Module
def dns_module():
    global dns_results
    dns_results = ''
    dns_results += "{}[+] Getting DNS information for {}{}{}{}\n\n".format(background, red, domain, reset, reset)
    try:
        dns_a_query = dns.resolver.resolve(domain, 'A')
        if dns_a_query:
            dns_results += "{}[+]{}{}A Record(s):{}".format(blue, reset, magenta, reset) + '\n'
            for a_record in dns_a_query:
                dns_results += "{}{}{}\n".format(green, a_record, reset)
        dns_results += '\n'
    except Exception as e:
        dns_a_query = None
        dns_results += "{}[-] Failed to fetch A Record for Domain {}: {}{}\n\n".format(red, domain, e, reset)
        pass
    try:
        dns_ns_query = dns.resolver.resolve(domain, 'NS')
        if dns_ns_query:
            dns_results += "{}[+]{}{}NS Record(s):{}\n".format(blue, reset, magenta, reset)
            for ns_record in dns_ns_query:
                dns_results += "{}{}{}\n".format(green, ns_record, reset)
        dns_results += '\n'
    except Exception as e:
        dns_ns_query = None
        dns_results += "{}[-] Failed to fetch NS Record for Domain {}: {}{}\n\n".format(red, domain, e, reset)
        pass
    try:
        dns_mx_query = dns.resolver.resolve(domain, 'MX')
        if dns_mx_query:
            dns_results += "{}[+]{}{}MX Record(s):{}\n".format(blue, reset, magenta, reset)
            for mx_record in dns_mx_query:
                dns_results += "{}{}{}\n".format(green, mx_record, reset)
        dns_results += '\n'
    except Exception as e:
        dns_mx_query = None
        dns_results += "{}[-] Failed to fetch MX Record for Domain {}: {}{}\n\n".format(red, domain, e, reset)
        pass
    try:
        dns_txt_query = dns.resolver.resolve(domain, 'TXT')
        if dns_txt_query:
            dns_results += "{}[+]{}{}TXT Record(s):{}\n".format(blue, reset, magenta, reset)
            for txt_record in dns_txt_query:
                dns_results += "{}{}{}\n".format(green, txt_record, reset)
    except Exception as e:
        dns_txt_query = None
        dns_results += "{}[-] Failed to fetch TXT Record for Domain {}: {}{}\n\n".format(red, domain, e, reset)
        pass
    print(dns_results)
dns_module()
# Geolocation Module
def geoloc_module():
    global geoloc_results
    geoloc_results = ''
    geoloc_results += "{}[+] Getting GEOLOCATION information for {}{}{}{}\n\n".format(background, red, domain, reset, reset)
    try:
        geolocdb_response = requests.request('GET', "https://geolocation-db.com/json/" + socket.gethostbyname(domain)).json() #This will do get req and convert domain to IP using socket
        geoloc_results += "{}[+]{}{}IP:{} {}{}{}\n".format(blue, reset, yellow, reset, white, geolocdb_response['IPv4'], reset)
        geoloc_results += "{}[+]{}{}Country:{} {}{}{}\n".format(blue, reset, yellow, reset, white, geolocdb_response['country_name'], reset)
        geoloc_results += "{}[+]{}{}Latitude:{} {}{}{}\n".format(blue, reset, yellow, reset, white, geolocdb_response['latitude'], reset)
        geoloc_results += "{}[+]{}{}Longitude:{} {}{}{}\n".format(blue, reset, yellow, reset, white, geolocdb_response['longitude'], reset)
    except:
        pass
    print(geoloc_results)
geoloc_module()
# Shodan Module
def shodan_module():
    if shodan_search_query:
        shodan_api = shodan.Shodan("<Your API KEY>") #Add Your API Key here ;)
        if ip_check(shodan_search_query) == "Invalid IP address":
            print("{}[+] Searching SHODAN for term {}{}{}{}".format(background, red, shodan_search_query, reset, reset))
            print()
            FACETS = [
                ('org', 3),
                ('domain', 3),
                ('port', 3),
                ('asn', 3),
                ('country', 3)
            ]
            FACET_TITLES = {
                'org': '{}[+]{}{} Top 3 Organizations:{}'.format(blue, reset, violet, reset),
                'domain': '{}[+]{}{} Top 3 Domains:{}'.format(blue, reset, violet, reset),
                'port': '{}[+]{}{} Top 3 Ports:{}'.format(blue, reset, violet, reset),
                'asn': '{}[+]{}{} Top 3 Autonomous Systems:{}'.format(blue, reset, violet, reset),
                'country': '{}[+]{}{} Top 3 Countries:{}'.format(blue, reset, violet, reset),
            }
            try:
                shodan_results = shodan_api.count(shodan_search_query, facets=FACETS)
                print("{}[+]{} {}Total Shodan results found for term {}{}{}:{} {}{}{}".format(blue, reset, green_bright, reset, shodan_search_query, magenta, reset, green, shodan_results['total'], reset))

                for facet in shodan_results['facets']:
                    print()
                    print(FACET_TITLES[facet])

                    for term in shodan_results['facets'][facet]:
                        print('{}%s{}: %s'.format(green, reset) % (term['value'], term['count']))
            except:
                pass
#The follwoing is the submodule of shodan only check IP
        if ip_check(shodan_search_query) == "Valid IP address":
            print("{}[+] Searching SHODAN for IP {}{}{}{}".format(background, red, shodan_search_query, reset, reset))
            try:
                host = shodan_api.host(shodan_search_query)
                print("""
{}[+]{}{}IP:{} {}{}{}
{}[+]{}{}Organization:{} {}{}{}
{}[+]{}{}Operating System:{} {}{}{}""".format(blue, reset, violet, reset, green, host['ip_str'], reset, blue, reset, violet, reset, green, host.get('org', 'n/a'), reset, blue, reset, violet, reset, green, host.get('os', 'n/a'), reset))
                ports_list = []
                for ports in host['data']:
                    ports_list.append(ports['port'])
                print(f"{blue}[+]{reset}{violet}Ports:{reset} {green}" + ", ".join(map(str, ports_list)))
            except:
                pass
shodan_module()

if(output_file):
    with open(output_file, 'w') as file:
        file.write(whois_results + '\n')
        file.write(dns_results + '\n')
        file.write(geoloc_results + '\n')
