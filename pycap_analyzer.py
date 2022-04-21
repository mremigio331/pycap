import sys
sys.setrecursionlimit(50000)
from alive_progress import alive_bar, config_handler
import json

import pycap_conversion as cap_con


def pcap_analyzer(pcap, export_file, all, name_lookup): #,virus_total,region)

    config_handler.set_global(length=40, bar='classic', enrich_print=False)

    pcaps = cap_con.pcap_to_json(pcap)

    total_ips = analyzer_loop(pcaps,name_lookup)



    if export_file == 'None':
        if all == True:
            print(total_ips['ips'])
        else:
            just_ips = total_ips['ips']
            top = sorted(just_ips.items(), key=lambda x: x[1]['total_count'], reverse=True)
            print(top[0:9])

    else:
        return total_ips
        #with open(export_file, 'w') as outfile:
        #    json.dump(total_ips, outfile)


def analyzer_loop(pcaps,name_lookup):
    total_ips = {'ips': {}}
    source_ips_list = []
    destination_ips_list = []
    host_names = []

    time_bar = len(pcaps)
    with alive_bar(time_bar) as bar:
        for x in pcaps:
            try:
                source_ip = x['_source']['layers']['ip']['ip.src']
                destination_ip = x['_source']['layers']['ip']['ip.addr']
                src_host = x['_source']['layers']['ip']['ip.src_host']

                if source_ip in total_ips['ips']:
                    source_count = total_ips['ips'][source_ip]['source_count']
                    source_count = source_count + 1
                    total_ips['ips'][source_ip].update({'source_count': source_count})

                    if source_ip not in source_ips_list:
                        source_ips_list.append(source_ip)

                    if name_lookup is True:
                        try:
                            if source_ip != src_host and source_ip not in host_names:
                                host_names.append(source_ip)
                                add_name = [src_host]
                                total_ips['ips'][source_ip].update({'name': add_name})

                            if source_ip != src_host and source_ip in host_names:
                                names = total_ips['ips'][source_ip]['name']
                                if src_host not in names:
                                    names.append(src_host)
                                    total_ips['ips'][source_ip].update({'name': names})

                        except:
                            pass

                if destination_ip in total_ips['ips']:
                    if destination_ip not in destination_ips_list:
                        destination_ips_list.append(destination_ip)

                    destination_count = total_ips['ips'][destination_ip]['destination_count']
                    destination_count = destination_count + 1
                    total_ips['ips'][destination_ip].update({'destination_count': destination_count})

                if source_ip not in total_ips['ips']:

                    if source_ip not in source_ips_list:
                        source_ips_list.append(source_ip)

                    source_ip_info = {source_ip: {'ip': source_ip,
                                                  'name': '',
                                                  'source_count': 1,
                                                  'destination_count': 0,
                                                  'total_count': 0,
                                                  'virus_total': '',
                                                  'country': '',
                                                  'region': ''
                                                  }
                                      }
                    total_ips['ips'].update(source_ip_info)

                    if name_lookup is True:
                        try:
                            if source_ip != src_host and source_ip not in host_names:
                                host_names.append(source_ip)
                                add_name = [src_host]
                                total_ips['ips'][source_ip].update({'name': add_name})

                            if source_ip != src_host and source_ip in host_names:
                                names = total_ips['ips'][source_ip]['name']
                                if src_host not in names:
                                    names.append(src_host)
                                    total_ips['ips'][source_ip].update({'name': names})

                        except:
                            pass

                if destination_ip not in total_ips['ips']:
                    if destination_ip not in destination_ips_list:
                        destination_ips_list.append(destination_ip)

                    destination_ip_info = {destination_ip: {'ip': destination_ip,
                                                            'name': '',
                                                            'source_count': 0,
                                                            'destination_count': 1,
                                                            'total_count': 0,
                                                            'virus_total': '',
                                                            'country': '',
                                                            'region': ''
                                                            }
                                           }
                    total_ips['ips'].update(destination_ip_info)

            except:
                pass
            bar()

    time_bar = len(total_ips['ips'])
    with alive_bar(time_bar) as bar:
        for x in total_ips['ips']:
            total_source = total_ips['ips'][x]['source_count']
            destination_count = total_ips['ips'][x]['destination_count']
            total_count = total_source + destination_count
            total_ips['ips'][x].update({'total_count': total_count})
            bar()

    potential_names_list = []
    for x in total_ips['ips']:
        if type(total_ips['ips'][x]['name']) == list:
            potential_names_list.append(total_ips['ips'][x])

    pcap_stats = {'total_packets': len(pcaps),
                  'total_ips': len(total_ips['ips']),
                  'total_source_ips': len(source_ips_list),
                  'total_destination_ips': len(destination_ips_list),
                  'total_potential_names': len(potential_names_list),
                  'potential_host_info': potential_names_list}

    total_ips.update({'statistics': pcap_stats})

    return total_ips



def stats(pcap):
    pcaps = cap_con.pcap_to_json(pcap)

    total_ips = analyzer_loop(pcaps, True)

    just_ips = total_ips['ips']

    top_total = sorted(just_ips.items(), key=lambda x: x[1]['total_count'], reverse=True)

    top_source = sorted(just_ips.items(), key=lambda x: x[1]['source_count'], reverse=True)

    top_dest = sorted(just_ips.items(), key=lambda x: x[1]['destination_count'], reverse=True)

    if len(top_total) > 10:
        top_10_total = top_total[0:10]

    else:
        amount = len(top_total) - 1
        top_10_total = top_total[0:amount]

    if len(top_source) > 10:
        top_10_source = top_source[0:10]

    else:
        amount = len(top_source) - 1
        top_10_source = top_source[0:amount]

    if len(top_dest) > 10:
        top_10_dest = top_dest[0:10]

    else:
        amount = len(top_dest) - 1
        top_10_dest = top_dest[0:amount]

    total_ips['statistics'].update({'top_ips': {}})
    total_ips['statistics']['top_ips'].update({'top_ips': [top_10_total]})
    total_ips['statistics']['top_ips'].update({'top_source': [top_10_source]})
    total_ips['statistics']['top_ips'].update({'top_dest': [top_10_dest]})

    return total_ips
