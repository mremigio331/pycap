
import pandas as pd
from alive_progress import alive_bar, config_handler

import pycap_conversion as cap_con

def cap_to_gephi(filename,export_name):

    pcaps = cap_con.pcap_to_json(filename)
    pcap_connections = []

    time_bar = len(pcaps)
    with alive_bar(time_bar) as bar:
        for x in pcaps:
            source_ip = x['_source']['layers']['ip']['ip.src']
            destination_ip = x['_source']['layers']['ip']['ip.dst']
            protocal = x['_source']['layers']['frame']['frame.protocols'].split('ip:')[1]
            line = {'Source': [source_ip],
                    'Target': [destination_ip],
                    'Type': ['Directed'],
                    'Connection': [protocal]}
            packet_info = pd.DataFrame(line)
            pcap_connections.append(packet_info)
            bar()

    frame = pd.concat(pcap_connections, axis=0, ignore_index=True)

    if export_name == 'NONE':
        save_name = export_name.split('.pcap')[0] + '.csv'
    else :
        save_name = export_name

    frame.to_csv(save_name, index=False)

    print('PCAP to Gephi completed')
