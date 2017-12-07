#!/usr/bin/python

# Python script to test for live hosts, services runnning on the hosts, virtual websites, web servers
# Example- ./multi-scanner.py -t 127.0.0.1-3 -o test --pingsweep --virtualhosts -w wordlist.txt --service --discover-webservers

# will.gould@cyberis.co.uk

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import subprocess as SP
import os
import multiprocessing
import socket
import time
import requests
import hashlib
import re
import urllib

from argparse import ArgumentParser


def print_banner():
    print("*" * 50)
    print("\n" + " " * 20 + "VHOST FUZZER \n")
    print("*" * 50)


def main():
    parser = ArgumentParser()
    parser.add_argument(
        "-t",
        dest="target_hosts",
        required=True,
        help="Enter a IP range or IP address")
    parser.add_argument(
        "-o",
        dest="output_directory",
        required=True,
        help="Set an output directory")
    parser.add_argument(
        "-w",
        dest="wordlist",
        required=False,
        help="Set a wordlist that will be used to find virtual hosts",
        default=False)
    parser.add_argument(
        "-p",
        dest="port",
        required=False,
        help="Set a port to use to run the vhost fuzzer on. Only needs to be set if they are hosting the site on a different port to the default.",
        default=80)
    parser.add_argument(
        "--pingsweep",
        dest="ping_sweep",
        action="store_true",
        help="Performs a ping sweep and discovers live hosts.",
        default=False)
    parser.add_argument(
        "--dns",
        dest="find_dns_servers",
        action="store_true",
        help="Find DNS servers from output",
        default=False)
    parser.add_argument(
        "--services",
        dest="perform_service_scan",
        action="store_true",
        help="Perform service scan over targets.",
        default=False)
    parser.add_argument(
        "--discover-webservers",
        dest="discover_web_servers",
        action="store_true",
        help="Attempt to discover web servers from the targets.txt file. It will store the output to web_servers.txt",
        default=False)
    parser.add_argument(
        "--virtualhosts",
        dest="virtualhosts",
        action="store_true",
        required=False,
        help="Attempt to discover virtual hosts  using the specified wordlist.",
        default=False)
    parser.add_argument(
        "--ss-output",
        dest="service_scan_output",
        required=False,
        help="--discover-webservers will use the output provided in this argument to find web servers.",
        default=False)

    arguments = parser.parse_args()
    output_directory = arguments.output_directory
    target_hosts = arguments.target_hosts
    output_file = output_directory + "/targets.txt"
    web_servers_output = output_directory + "/web_servers.txt"
    ss_output = arguments.service_scan_output

    if len(sys.argv) == 1:
        print_banner()
        parser.error("No arguments. Please Provide arguments.")
        sys.exit()

    #  HOST DISCOVERY
    if arguments.ping_sweep is True:

        print("[#] Performing ping sweep")
        print("[+] Writing discovered targets to: %s" % output_file)
        live_hosts = 0
        f = open(output_file, 'w')

        print("[+] Performing ping sweep over %s" % target_hosts)

        SWEEP = "nmap -n -sS -p0- %s" % (target_hosts)
        results = SP.check_output(SWEEP, shell=True, bufsize=1, stderr=SP.PIPE)
        print ("    [>] Ping Sweep results")
        print results
        lines = results.split("\n")

        for line in lines:
            line = line.strip()
            line = line.rstrip()
            if ("Nmap scan report for" in line):
                ip_address = line.split(" ")[4]
                if (live_hosts > 0):
                    f.write('\n')
                f.write("%s" % (ip_address))
                print("   [>] Discovered host: %s" % (ip_address))
                live_hosts += 1
        print("[*] Found %s live hosts" % (live_hosts))
        print("[*] Created target list %s" % (output_file))
        f.close()

    #  SERVICE SCAN
    if arguments.perform_service_scan is True:
        print("[#] Performing service scans")
        print("[+] Starting nmap scan for %s" % (target_hosts))
        SSCAN = "nmap -sV --top-ports 50 -iL %s -oA '%s/%s.ss'" % (
            output_file, output_directory, target_hosts)
        results = SP.check_output(SSCAN, shell=True, bufsize=1, stderr=SP.PIPE)
        print("    [>] SERVICE SCAN RESULTS ")
        print (results)

    # discover web servers
    if arguments.discover_web_servers is True:
        print("[#] Attempting to find web servers")
        print("[+] If successful it will store the output to web_servers.txt")
        if arguments.perform_service_scan is True:
            print("[#] Found Service scan output. Using this to determine web servers")
            f = output_directory + "/" + target_hosts + ".ss.gnmap"
            w = web_server_discover()
            w.discover(f,web_servers_output)
        else:
            print ("[#] No service Scan Output found using output provided.")
            if ss_output == False:
                print("[!] No output provided")
            else:
                print("[+] Found output. Starting the web server discovery.")
                f = ss_output
                w = web_server_discover()
                w.discover(f,web_servers_output)

    #  vhost fuzzer
    if arguments.virtualhosts is True:
        print("[#] Performing VHOST fuzzing")
        scanner = virtual_host_scanner(
            output_file,
            arguments.output_directory,
            arguments.port,
            arguments.wordlist)
        scanner.scan()

#                               CLASSES
class bcolors:
    R = '\33[91m'
    G = '\33[92m'
    Y = '\33[93m'
    ENDC = '\033[0m'


class status_c:

    def __int__(self):
        self.code = code

    def code_handler(self, code):
        if code >= 200 and code <= 299:
            return bcolors.G + str(code) + bcolors.ENDC
        elif code >= 400 and code <= 499:
            return bcolors.Y + str(code) + bcolors.ENDC
        else:
            return bcolors.R + str(code) + bcolors.ENDC

class web_server_discover(object):

    def __int__(self,output, web_servers_output):
        self.output = output
        self.web_servers_output = web_servers_output

    def discover(self, output, web_servers_output):
        web_keys = ['80/open', '443/open', '8080/open', '//http//']
        w = open(web_servers_output, "w")
        f = open(output)
        ips = []
        lines = f.readlines()
        print("[+] grabbing output from service scan")
        for line in lines:
            line = line.strip()
            line = line.rstrip()
            # print (line)
            if ("Ports:" in line):
                for wk in web_keys:
                    if wk in line:
                        # ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
                        ip = line.split(" ")[1]
                        ips.append(ip)
                        i = list(set(ips))
                        print (i)
                    else:
                        continue
        print("[#] Writing ips found to output file.")
        w.write('%s' % (i))
        w.write('\n')
        w.close()

class vhost_functions:

    def __int__(self):
        self.ipaddress = ip

    def lookup_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)
        except socket.herror:
            return None, None, None

class virtual_host_scanner(object):

    def __init__(
            self,
            target,
            output,
            port=80,
            wordlist="wordlist.txt"):
        self.target = target
        self.output = output + '/' + 'virtualhosts_output.txt'
        self.port = port
        self.wordlist = wordlist

    def scan(self):
        print(
                "[+] Starting virtual host scan for %s using port %s and wordlist %s" %
                (self.target, str(
                    self.port), self.wordlist))

        if not os.path.exists(self.wordlist):
            print(
                    "[!] Wordlist %s doesn't exist, exiting virtual host scanner." %
                    self.wordlist)
            return

        virtual_host_list = open(self.wordlist).read().splitlines()
        results = ''
        f = open(self.output, "w")
        s = status_c()
        vf = vhost_functions()

        for virtual_host in virtual_host_list:
            ips = open(self.target, "r")
            lines = ips.readlines()
            lines = map(lambda s: s.strip(), lines)
            for ip in lines:
                DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) ' \
                                     'AppleWebKit/537.36 (KHTML, like Gecko) ' \
                                     'Chrome/61.0.3163.100 Safari/537.36'

                DN_DATA = vf.lookup_hostname(ip)
                DN = repr(DN_DATA[0]).replace("'", "")

                virtual_hostname = virtual_host.replace('%s', self.target)

                headers = {
                    'Host': virtual_hostname + "." + DN if self.port == 80 else '{}:{}'.format(
                        hostname,
                        self.port),
                    'Accept': '*/*',
                    'user-agent': DEFAULT_USER_AGENT}

                dest_url = '{}://{}:{}'.format('https' if int(
                    self.port) == 443 else 'http', ip, self.port)

                res = requests.get(dest_url, headers=headers, verify=False)

                output = '   [>] Found: {} (code: {}, length: {}, content-type: {}, server: {}) on {}'.format(
                    virtual_hostname,
                    s.code_handler(
                        res.status_code),
                    res.headers.get('content-length'),
                    res.headers.get('content-type'),
                    res.headers.get('server'),
                    ip)
                # print("   [>] Writing output to file")
                f.write('\n')
                f.write('%s' % (output))
                results += output + '\n'

                print(output)


if __name__ == "__main__":
    main()
