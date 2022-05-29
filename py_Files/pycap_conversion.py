import os
import json


def pcap_to_json(pcap):
    print('Converting PCAP to JSON...')

    tshark = 'tshark -r ' + pcap + ' -T json > Data/holding_area/output.json'
    os.system(tshark)

    f = open('Data/holding_area/output.json', )
    os.remove('Data/holding_area/output.json')

    pcaps = json.load(f)

    print('PCAP Converted')

    return pcaps