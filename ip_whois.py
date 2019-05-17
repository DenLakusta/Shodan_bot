import requests
import json
import config_shodan
import re
import shodan
import sys
import time

SHODAN_API_KEY = 'FmncKZw0VohGwWSfJtCLEdUDvdeljtXi'
api = shodan.Shodan(SHODAN_API_KEY)
url = 'http://ip-api.com/json/'


def get_ip_from_host(hostname):
    try:
        dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' + hostname + '&key=' + config_shodan.SHODAN_API_KEY
        # First we need to resolve our targets domain to an IP
        resolved = requests.get(dnsResolve)
        hostIP = resolved.json()[hostname]
    except:
        hostIP = 'WRONG HOST'
    return hostIP


def get_json_whois(ip):
    url = 'http://ip-api.com/json/'
    url = url + str(
        ip) + '?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query'
    response_ip = requests.get(url).json()
    print(response_ip)
    ip_info = ''
    try:
        req = response_ip['query']
    except:
        req = ''

    try:
        asa = response_ip['as']
    except:
        asa = ''
    try:
        city = response_ip['city']
    except:
        city = ''
    try:
        region = response_ip['regionName']
    except:
        region = ''
    try:
        country = response_ip['country']
    except:
        country = ''

    try:
        org = response_ip['org']
    except:
        org = ''
    try:
        status = response_ip['status']
    except:
        status = ''
    ip_info += 'HOST: {}\nAS: {}\nCOUNTRY: {}\nREGION: {}\nCITY: {}\nORG: {}\nSTATUS: {}'.format(req, asa, country, region, city, org, status)

    return ip_info


def main():
    print(get_json_whois('124.34.56.32'))


if __name__ == '__main__':
    main()
