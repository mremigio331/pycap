"""

"""
import sys

import pycap_gephi as geph
import pycap_analyzer as lyzer



def pycap_stats(pcap, output_file):
    stats = lyzer.stats(pcap)
    total_packets = stats['statistics']['total_packets']
    total_ips = stats['statistics']['total_ips']
    total_source = stats['statistics']['total_source_ips']
    total_destinations = stats['statistics']['total_destination_ips']
    potential_names = stats['statistics']['total_potential_names']

    print('Total Packets: ' + str(total_packets))
    print('Total Unique IPs: ' + str(total_ips))
    print('Total Source IPs: ' + str(total_source))
    print('Total Destination IPs: ' + str(total_destinations))
    print('Total Potential Names: ' + str(potential_names))
    print(' \n')
    print('Top IP Statistics')
    print('\n')

    top_number = 1
    print('Top IPs in the PCAPs')
    for x in stats['statistics']['top_ips']['top_ips'][0]:
        ip = x[1]['ip']
        total_count = x[1]['total_count']
        source_count = x[1]['source_count']
        dest_count = x[1]['destination_count']
        names = x[1]['name']
        print(str(top_number) + '. ' +
              ip +
              ' (potential names: {' + str(names) +
              '}) had a total count of ' + str(total_count) +
              ', total source count of ' + str(source_count) +
              ', and a destination count of ' + str(dest_count))
        top_number += 1

if '-O' in sys.argv:
    output_file = sys.argv[sys.argv.index('-O') + 1]
else:
    output_file = ''

if '-p' in sys.argv:
    pcap = sys.argv[sys.argv.index('-p') + 1]
else:
    print('Use -p to add a .pcap file.')
    sys.exit()


if ('-s' in sys.argv) or ('-statistics' in sys.argv):
    """
    """
    #if output_file != '':
    pycap_stats(pcap,'')


if ('-g' in sys.argv) or ('-gephi' in sys.argv):
    """
    """
    file_name = pcap
    export_name = output_file

    geph.cap_to_gephi(file_name, export_name)



if ('-h' in sys.argv) or ('-help' in sys.argv):
    """
    The -h or -help flag will print in the terminal all available flags
    """
    print('*** Commands ***')
    print('-g  -gephi      analyzes pcap and exports file for gephi')
    print('-O  -outfile    declares the filename')
    print('-p  -pcap       identifies the pcap file')
    print('-s  -stats      prints statistical data from the pcap')



