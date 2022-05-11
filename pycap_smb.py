import sys

import pycap_gephi as gephi
import pycap_analyzer as analyzer
import pycap_outputs as outputs


def file_name_discovery(pcap,output_file):

    file_names = analyzer.file_name_discovery(pcap)

    if '.txt' in output_file:
        outputs.file_discovery_txt_output(file_names, output_file)

    if '.json' in output_file:
        outputs.file_discovery_json_output(file_names, output_file)

    else:
        outputs.file_discovery_print_output(file_names)


if '-O' in sys.argv:
    output_file = sys.argv[sys.argv.index('-O') + 1]
else:
    output_file = ''

if '-p' in sys.argv:
    pcap = sys.argv[sys.argv.index('-p') + 1]
else:
    print('Use -p to add a .pcap file.')
    sys.exit()


if ('-h' in sys.argv) or ('-help' in sys.argv):
    """
    The -h or -help flag will print in the terminal all available flags
    """
    print('*** Commands ***')
    print('-O  -outfile    declares the filename')
    print('-p  -pcap       identifies the pcap file')
    
file_name_discovery(pcap,output_file)


