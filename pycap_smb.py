import sys

import pycap_gephi as gephi
import pycap_analyzer as analyzer
import pycap_conversion as con
import pcap_outputs as outputs


def file_name_discovery(pcap,output_file):

    file_names = analyzer.file_name_discovery(pcap)

    if '.txt' in output_file:
        outputs.file_discovery_txt_output(file_names, output_file)

    if '.json' in output_file:
        outputs.file_discovery_json_output(file_names, output_file)

    else:
        outputs.file_discovery_print_output(file_names)



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


