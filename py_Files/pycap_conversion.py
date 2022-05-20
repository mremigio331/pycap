import os
import json


def pcap_to_json(pcap):
    print('Converting PCAP to JSON...')
    tshark = 'tshark -r ' + pcap + ' -T json > output.json'
    os.system(tshark)

    f = open('output.json', )
    os.remove('output.json')

    pcaps = json.load(f)

    print('PCAP Converted')

    return pcaps