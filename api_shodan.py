import requests
import json
import config_shodan
import re
import shodan
import sys
import time
import ujson
import ip_whois


SHODAN_API_KEY = 'FmncKZw0VohGwWSfJtCLEdUDvdeljtXi'
api = shodan.Shodan(SHODAN_API_KEY)


def get_ip_json(ip):
    """ Return JSON full search result by IP """
    host = {}
    try:
        ip_info = api.host(ip)
        host = ip_info
         # Using SHODAN api for geting json about IP
    except shodan.APIError as e:
        error_shodan = str(e)
        host.update({'error': error_shodan})
        # host = 'Invalid IP'

    except BaseException as error:
        error_base = str(error)
        host.update({'error': error_base})
        # host = 'Invalid IP'

    return host


def vulns_simple(ip):
    vulns_all = ''
    host = get_ip_json(ip)
    if host != 'Invalid IP':
        try:
            cve = host['vulns']
        except:
            cve = 'NO VULNERABILITIES'
    elif host == 'Invalid IP':
        cve = ''
    if cve != 'NO VULNERABILITIES' and len(cve) > 0:
        for item in host['data']:
            vulns = item.get('vulns')
            if vulns != None:
                try:
                    for i in cve:
                        vulns_all += "\n\nVULNERABILITY: {}\nDESCRIBTION: {}".format(i, vulns[i]['summary'])
                except shodan.APIError as e:
                    # print("Error %s " % (e))
                    vulns_all += str(e)
                except BaseException as error:
                    # print("Error %s " % (error))
                    vulns_all += str(error)
    else:
        vulns_all = 'NO VULNERABILITIES'
    return vulns_all


def get_ip_info(host):

    """Collecting base information about IP from recieved JSON"""

    base_info = ''
    try:
        if host.get('error') == None:
        # if host != 'Invalid IP':
            ip = host['ip_str']
            org = host.get('org', 'n/a')
            os = host.get('os', 'n/a')
            try:
                for item in host['data']:
                    country = item['location'].get('country_name')
                    location = item['location'].get('city')
            except shodan.APIError as e:
                base_info = str(e)
            except BaseException as error:
                print(error)
            try:
                base_info = "IP: {}\nORGANIZATION: {}\nOPERATING_SYSTEM: {}\nCOUNTRY: {}\nLOCATION: {}".format(str(ip), str(org), str(os), str(country), str(location))
            except BaseException as error:
                base_info = str(error)
        else:
        # if host == 'Invalid IP':
            base_info = host.get('error')
    except shodan.APIError as e:
        print(str(e))

    except BaseException as error:
        print(str(error))


    return base_info


def get_host_name(host):

    """ Collecting hosts and domains by IP from JSON"""
    domains_all = ''
    hostnames_all = ''
    if host.get('error') == None:
        for item in host['data']:
            try:
                domains = item['domains']
                for domain in domains:
                    if domain not in domains_all:
                        domains_all += domain.strip() + ' '
            except:
                domain = 'NO DATA'
            try:
                hostnames = item['hostnames']
                for hostname in hostnames:
                    if hostname not in hostnames_all:
                        hostnames_all += hostname + ' '
            except:
                hostnames = 'NO DATA'
        hostname_and_domain = "HOSTNAMES: {}\nDOMAINS: {}\n".format(domains_all, hostnames_all)
    else:
        hostname_and_domain = ''
    return hostname_and_domain


def get_port_sevices(host):
    """Collect information about ports, services and servers from JSON"""

    service_port = ''
    if host.get('error') == None:
        for item in host['data']:
            try:
                port = item['port']
                if port == None:
                    port = ''
            except:
                port = 'NO DATA'
            try:
                product = item['product']
                if product == None:
                    product = ''
            except:
                product = ''
            try:
                info = item['info']
                if info == None:
                    info = ''
            except:
                info = ''

            try:
                buner_long = item['data']
                buner_len = buner_long.find('\n')
                buner_short = buner_long[:buner_len]
                if buner_long == None:
                    buner_short = ''
            except:
                buner_short = ''
            try:
                server = item['http']['title']
                if server == None:
                    server = 'NO DATA'
            except:
                server = 'NO SERVER DATA'

            # service_port += '\n' + buner_short+'\n'
            if server != 'NO SERVER DATA':
                service_port += '\n' + 'PORT: ' + str(port) + ' ' + product + '  ' + info + '\n' + buner_short + '\n' + 'SERVER: ' + server + '\n'
                # service_port += '\n' + 'PORT: ' + str(port) + ' ' + product + '  ' + info + '\n' + 'SERVER: ' + server
            else:
                service_port += '\n' + 'PORT: ' + str(port) + ' ' + product + '  ' + info + '\n' + buner_short + '\n'
    elif host.get('error') != None:
        service_port = ''
    return service_port

#### This func collect results of previous funcs to make response fo base info button by IP

def return_result_ip(ip):
    host = get_ip_json(ip)
    if host.get('error') == None:
        ip_info = get_ip_info(host)
        hostname_domains = get_host_name(host)
        services = get_port_sevices(host)
        text =  ip_info + '\n' + hostname_domains + services
    else:
        text = host.get('error')
    return text


# Next code is to find IP from hostname and return result
# and if we find IP next use all previous function to get all information
def get_ip_from_host(hostname):
    try:
        dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' + hostname + '&key=' + config_shodan.SHODAN_API_KEY
        # First we need to resolve our targets domain to an IP
        resolved = requests.get(dnsResolve)
        hostIP = resolved.json()[hostname]
    except shodan.APIError as e:
        print(str(e))
    except BaseException as error:
        print(error)
    return hostIP

#### This func collect results of previous funcs to make response fo base info button by DOMAIN

def response_hostname(hostname):

    ip = get_ip_from_host(hostname)
    if ip != None:
        host = get_ip_json(ip)
        if host.get('error') == None:
            ip_info = get_ip_info(host)
            hostname_domains = get_host_name(host)
            services = get_port_sevices(host)
            text =  ip_info + '\n' + hostname_domains + services
        elif host.get('error') != None:

            result = 'SHODAN: ' + '\n' + host.get('error') + '\n' + 'WHOIS: ' + '\n' + ip_whois.get_json_whois(ip)
            ip_s = dns_search(hostname)
            if len(ip_s) > 0:
                ip_s_text = ''
                for ip in ip_s:
                    ip_s_text += ip + '\n'
                text = result + '\n' + "IP's WITH DNS RECORDS {}".format(hostname) + '\n' + ip_s_text
            else:
                text = result
    else:
        text = 'WRONG HOST'
    return text


def response_hostname_for_ful(hostname):
    ip = get_ip_from_host(hostname)
    if ip != None:
        host = get_ip_json(ip)
        if host.get('error') == None:
            ip_info = get_ip_info(host)
            hostname_domains = get_host_name(host)
            services = get_port_sevices(host)
            text =  ip_info + '\n' + hostname_domains + services
        elif host.get('error') != None:

            text = 'SHODAN: ' + '\n' + host.get('error') + '\n' + 'WHOIS: ' + '\n' + ip_whois.get_json_whois(ip)

        else:
            text = 'WRONG HOST'
    return text


# This function use hostnames an domains to find other subdomains and IP's
def dns_search(hostname):
    time.sleep(1)
    results = api.search('hostname:{}'.format(hostname))
    ip_s= set()
    for item in results['matches']:
        ip_host = item['ip_str']
        ip_s.add(ip_host)
    return ip_s


def get_related_ip(ip):
    host = get_ip_json(ip)
    ip_all = set()
    related_ip = '\n\nRELATED IP:\n'
    domains_all = []

    if host.get('error') == None:
        try:
            ip_self = host['ip_str']

            for item in host['data']:
                domains = item['domains']
            if len(domains) > 0:
                for domain in domains:
                    time.sleep(1)
                    ip_s = dns_search(domain)
                    for ip in ip_s:
                        ip_all.add(ip)
                try:
                    ip_resolver = get_ip_from_host(domain)
                except:
                    ip_resolver = 'NO DNS RESOLVER'
                if ip_resolver != 'NO DNS RESOLVER':
                    ip_all.add(ip_resolver)
            else:
                related_ip = '\nNO RELATED IP'
        except shodan.APIError as e:
            ip_all = e
        except BaseException as error:
            print(error)

    if related_ip != 'NO RELATED IP':
        if len(ip_all) > 0 and len(ip_all) < 50:
            ip_all = list(ip_all)
            for ip in ip_all:
                if ip_self != ip and ip != None:
                    try:
                        time.sleep(1)
                        host = get_ip_json(ip)
                        if host.get('error') == None:
                            dns = get_host_name(host)
                        else:
                            dns = 'NO HOSTS'
                    except shodan.APIError as e:
                        dns = str(e)
                    except BaseException as error:
                        print(error)
                        dns = 'SOMETHING WENT WRONG'
                    related_ip += 'IP: {}\n{}\n'.format(ip, dns)
        elif len(ip_all) > 50:
            ip_all = list(ip_all)
            for ip in ip_all[:51]:
                if ip_self != ip and ip != None:
                    try:
                        time.sleep(1)
                        host = get_ip_json(ip)
                        if host.get('error') == None:
                            dns = get_host_name(host)
                        else:
                            dns = 'NO HOSTS'
                    except shodan.APIError as e:
                        dns = str(e)
                    except BaseException as error:
                        print(error)
                    related_ip += 'IP: {}\n{}\n'.format(ip, dns)
            related_ip += '\n' + 'YOUR REQUEST IS TOO BIG. IT CONTAINS MORE THAN 50 HOSTS. PLEASE USE WEB SHODAN FOR FULL INFO'

    return related_ip




def get_related_hosts(hostname):
    all_dns = '\n\nRELATED HOSTS:\n'
    # ip_all = set()
    ip_all = dns_search(hostname)
    # for ip in ip_s:
    #     ip_all.add(ip)
    try:
        ip_resolver = get_ip_from_host(hostname)
        # print(ip_resolver)
        if ip_resolver != None:
            ip_all.add(ip_resolver)
        # print(ip_s)
    except shodan.APIError as e:
        print(e)

    except BaseException as error:
        print(error)

    if len(ip_all) > 0 and len(ip_all) < 50:
        ip_all = list(ip_all)
        for ip in ip_all:
            try:
                host = get_ip_json(ip)
                time.sleep(1)
                if host.get('error') == None:
                    dns = get_host_name(host)
                else:
                    dns = 'NO HOSTS'
            except shodan.APIError as e:
                dns = str(e)
            except BaseException as error:
                print(error)
            all_dns += 'IP: {}\n{}\n'.format(ip, dns)
    elif len(ip_all) > 50:
        ip_all = list(ip_all)
        for ip in ip_all[:51]:
            try:
                host = get_ip_json(ip)
                time.sleep(1)
                if host.get('error') == None:
                    dns = get_host_name(host)
                else:
                    dns = 'NO HOSTS'
            except shodan.APIError as e:
                dns = str(e)
            except BaseException as error:
                print(error)
            all_dns += 'IP: {}\n{}\n'.format(ip, dns)
        all_dns += '\n' + 'YOUR REQUEST IS TOO BIG. IT CONTAINS MORE THAN 50 HOSTS. PLEASE USE WEB SHODAN FOR FULL INFO'
    else:
        all_dns = '\nNO RELATED HOSTS'
    return all_dns


def full_info_ip(ip):
    base = return_result_ip(ip)
    vulns = vulns_simple(ip)
    related_ip = get_related_ip(ip)
    full_info = base + '\n' + vulns + '\n' + related_ip
    return full_info


def full_info_hostname(hostname):
    base = response_hostname_for_ful(hostname)
    ip = get_ip_from_host(hostname)
    vulns = vulns_simple(ip)
    related_hosts = get_related_hosts(hostname)
    full_info = base + '\n' + vulns + '\n' + related_hosts
    return full_info



def write_json(data, filename ='shodan.json'):
    with open(filename, 'w', encoding='utf8') as f:
        json.dump(data, f, indent=2, skipkeys=True)


def main():
    print(response_hostname('dans.gov.ua'))
    # print(get_related_hosts('choopa.net'))
    # print(get_related_ip('68.232.185.87'))
    # print(full_info_ip('194.44.166.178'))
    # print(get_ip_from_host('choopa.net'))
    # print(parts_message(return_vulns('212.26.142.164')))
    # print(get_dns_info('mtu.gov.ua'))
    # print(dns_search('mty.gov.ua'))
    # print(get_ip_from_host('mty.gov.ua'))
    # print(get_host_name('195.191.39.30'))
    # print(dns_search('195.191.39.242'))
    # print(parts_message(return_vulns('212.26.142.164')))
    # print(get_vulns(get_ip_json('212.26.142.164')))
    # print(return_result_ip('68.232.185.118'))
    # print(return_exploit('82.207.94.222'))
    # print(get_vulns(get_ip_json('91.198.247.183')))
    # print(response_hostname('mty.gov.ua'))
    # print(vulns_simple('212.26.142.164'))
    # print(return_vulns('212.26.142.164'))
    # print(get_ip_from_host('mty.gov.ua'))
    # print(search_exploit(get_vulns(get_ip_json('212.26.142.164'))))
    # print(get_ip_json('68.232.185.87'))
    # print(get_ip_info(get_ip_json('68.232.185.118')))
if __name__ == '__main__':
    main()
