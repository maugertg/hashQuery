import os
import sys

import ipaddress
import configparser
from IPy import IP

from datetime import datetime
from threatgrid import Threatgrid

def sort_ip_list(ip_list):
    """Sort a list of IP address numerically"""
    return sorted(ip_list, 
      key=lambda ip:IP(ip).int())

def print_sid_ips(ip_addresses_by_sample):
    """Print the SID followed by list of unique IP address 1 per line"""
    for SID in ip_addresses_by_sample:
        print('\n',SID)
        for ip in ip_addresses_by_sample[SID]:
            print(' ',ip)

def print_sid_domains(domains_by_sample):
    """Print the SID followed by list of unique domains address 1 per line"""
    for SID in domains_by_sample:
        print('\n',SID)
        for domain in sorted(domains_by_sample[SID]):
            print(' ',domain)

def print_sid_domains_ips(ip_addresses_by_sample, domains_by_sample):
    """Print the SID followed by list of unique ips and domains address 1 per line"""
    for SID in ip_addresses_by_sample:
        print('\n',SID)
        for ip in ip_addresses_by_sample[SID]:
            print(' ',ip)
        for domain in sorted(domains_by_sample[SID]):
            print(' ',domain)

def print_all_ips(ip_addresses):
    """Print all of the IPs found"""
    print('\nFound %d IP Addresses:' % len(ip_addresses))
    for ip in sort_ip_list(ip_addresses):
        print(' ',ip)

def print_all_domains(domains):
    """Print all of the domains found"""
    print('\nFound %d domains:' % len(domains))
    for domain in sorted(domains):
        print(' ',domain)

def write_sample_info (JSON_output, timestamp):
    """
    Create a file in the results directory named with the HASH and timestamp
    Write the SID followed by a list of unique IPs and then unique domains
    that are associated with that sample
    """
    for hash in JSON_output:
        f = open('RESULTS/%s_%s_sample_info.txt' % (hash, timestamp),'w')
        for SID in JSON_output[hash]:
            f.write('\n%s\n' % SID)
            if JSON_output[hash][SID]['IPS'][0] == 'No External IP Addresses found':
                f.write('No External IP Addresses found\n')
            else:
                for IP in sort_ip_list(JSON_output[hash][SID]['IPS']):
                    f.write('%s\n' % IP)
            for Domain in sorted(JSON_output[hash][SID]['DOMAINS']):
                f.write('%s\n' % Domain)
        f.close()

def print_count_over_threshold(sample_ids_scores, threashold):
    print('%s of the samples had a Threat Score greater than %s' % (len(sample_ids_scores),threashold))

def write_samples_over_threshold(intput_file_name, timestamp, threashold, sample_ids_scores):
    with open('RESULTS/%s_%s_SIDS_over_%s.csv' % (intput_file_name, timestamp, threashold),'a') as checksumHit:
        for tup in sample_ids_scores:
            checksumHit.write('%s,%s\n' % (tup[0],tup[1]))

def write_samples_over_threshold_json(JSON_output, intput_file_name, timestamp, threashold):
    for hash in JSON_output:
        f = open('RESULTS/%s_%s_SIDS_over_%s.csv' % (intput_file_name, timestamp, threashold),'a')
        f.write('\n%s\n' % hash)
        for SID in JSON_output[hash]:
            SCORE = JSON_output[hash][SID]['THREATSCORE']
            if SCORE >= threashold:
                f.write('%s,%s\n' % (SID,SCORE))
        f.close()

def read_threat_grid_config(config_file = 'api.cfg'):
    # Reading the config file to get settings
    config = configparser.RawConfigParser()
    config.read(config_file)

    api_key = config.get('Main', 'api_key')
    host_name = config.get('Main', 'host_name')

    return api_key, host_name


def setup(config_func):
    # Setup Threat Grid client
    api_key, host_name = config_func()
    return Threatgrid(host_name, api_key)

def write_hash_hit_or_miss(intput_file_name, file_name_timestamp, hit_or_miss, hash):
    with open(f'RESULTS/{intput_file_name}_{file_name_timestamp}_{hit_or_miss}.txt', 'a') as file:
        file.write(f'{hash}\n')

def read_input_file(file_name):
    with open(file_name, 'r') as f:
        for line in f:
            yield line.strip()


def main():
    # Get the timestamp of when the script started and format the timestamp so it can be used in a file name
    file_name_timestamp = datetime.now().strftime("%Y-%m-%d_%H.%M.%S")

    # Validate a list of hashes was provided as an argument
    if len(sys.argv) < 2:
        sys.exit('Usage:\n python %s hash_list.txt' % os.path.basename(__file__))

    input_file = sys.argv[1]

    # Validate the provided list of hashes exists
    if not os.path.isfile(str(input_file)):
        sys.exit ('File %s doesn\'t exist' % input_file)

    # Store the name of the file that contains the hashes
    intput_file_name = os.path.basename(input_file)

    # Setup Threat Grid API client
    tg_client = setup(read_threat_grid_config)

    # Storage containers for ouput 
    sample_ids = set()
    sample_ids_scores = []
    ip_addresses = []
    ip_addresses_by_sample = {}
    domains = []
    domains_by_sample = {}
    hash_matches = []
    JSON_output = {}
    threashold = 70

    # Create RESULTS directory if it does not exist
    if not os.path.exists('RESULTS'):
        os.makedirs('RESULTS')

    # Count number of lines in input_file
    with open(input_file,'r') as input_list:
        lines = sum(1 for line in input_list)

    input_observables = read_input_file(input_file)

    # Validate if each hash exists, if it does save all of the Sample IDs
    for line, hash in enumerate(input_observables):
        line = line + 1
        url_search_submissions = f'/search/submissions?q={hash}'
        query = tg_client.query_api(url_search_submissions)

        if query['data']['current_item_count'] == 0:
            print('Line %d of %d :-(' % (line, lines))
            write_hash_hit_or_miss(intput_file_name, file_name_timestamp, "miss", hash)
        else:
            print('Line %d of %d is a Winner! - %s' % (line, lines, hash))
            hash_matches.append(hash)
            write_hash_hit_or_miss(intput_file_name, file_name_timestamp, "hits", hash)

            for i in query['data']['items']:
                item = i.get('item', {})
                SID = item['sample']
                threat_score = item.get('analysis', {}).get('threat_score', '000')
                sample_ids.add(SID)
                JSON_output.setdefault(hash, {}).setdefault(SID, {'IPS': [], 'DOMAINS': [], 'THREATSCORE': threat_score})

    # Print the number of hashes found
    print('\nFound %d out of %d hashes in the system' % (len(hash_matches),lines))

    # Print the number of samples found
    print('\nFound %d samples from %d hashes:' % (len(sample_ids),len(hash_matches)))

    # Query each Sample ID and get all of the IPs and Domains
    for hash in JSON_output:
        current_hash = hash
        for SID in JSON_output[hash]:

            #/api/v2/samples/SID/analysis/network_streams?api_key=API_KEY
            url_network_streams = f'/samples/{SID}/analysis/network_streams'
            analysis_elements = tg_client.query_api(url_network_streams)
            network_streams = analysis_elements['data']['items']

            ip_addresses_by_sample[SID] = []
            domains_by_sample[SID] = []

            for stream in network_streams:
                dst_port = network_streams[stream]['dst_port']
                current_ip = network_streams[stream]['dst']

                # Verify traffic is to a public IP and add it to the list
                if IP(current_ip).iptype() == 'PUBLIC':
                    if current_ip not in ip_addresses:
                        ip_addresses.append(current_ip)
                        with open('RESULTS/%s_%s_ips.txt' % (current_hash, file_name_timestamp),'a') as ipFound:
                            ipFound.write('%s\n' % current_ip)

                    if current_ip not in ip_addresses_by_sample[SID]:
                        ip_addresses_by_sample[SID].append(current_ip)
                        JSON_output[current_hash][SID]['IPS'].append(current_ip)

                if dst_port == 53  and network_streams[stream]['protocol'] == 'DNS':
                    option = network_streams[stream]['decoded']
                    for keys in option:
                        current_domain = option[keys]['query']['query_data']

                        if current_domain != 'workstation':
                            if current_domain not in domains and current_domain != 'time.windows.com':
                                domains.append(current_domain)
                                with open('RESULTS/%s_%s_domains.txt' % (current_hash, file_name_timestamp),'a') as domainFound:
                                    domainFound.write('%s\n' % current_domain)
                            if current_domain not in domains_by_sample[SID]:
                                domains_by_sample[SID].append(current_domain)
                                JSON_output[current_hash][SID]['DOMAINS'].append(current_domain)

            if len(ip_addresses_by_sample[SID]) == 0:
                no_ips = 'No External IP Addresses found'
                ip_addresses_by_sample[SID].append(no_ips)
                JSON_output[current_hash][SID]['IPS'].append(no_ips)
            if len(domains_by_sample[SID]) == 0:
                no_domains = 'No domains found'
                domains_by_sample[SID].append(no_domains)
                JSON_output[current_hash][SID]['DOMAINS'].append(no_domains)


    print_all_ips(ip_addresses)
    print_all_domains(domains)
    # write_sample_info(JSON_output, timestamp)


if __name__ == "__main__":
    main()