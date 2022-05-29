import json

def file_discovery_txt_output(packets,filename):

    print('Exporting data to ' + filename)
    total_ips = packets
    just_ips = total_ips['ips']
    top_total = sorted(just_ips.items(), key=lambda x: x[1]['total_count'], reverse=True)
    just_files = total_ips['files']
    top_files = sorted(just_files.items(), key=lambda x: x[1]['total_count'], reverse=True)

    ip_count = len(top_total)
    file_count = len(top_files)

    print('Total IP Count: ' + str(ip_count) + '\n')
    print('Total File Count: ' + str(file_count) + '\n\n')


    with open(filename, 'w') as f:
        f.write('SMB2 Traffic \n\n')
        f.write('Total IP Count: ' + str(ip_count) + '\n')
        f.write('Total File Count: ' + str(file_count) + '\n\n')
        f.write('Unique IPs\n\n')
        for x in top_total:
            ip = x[0]
            count = str(total_ips['ips'][ip]['total_count'])
            files = str(total_ips['ips'][ip]['files'])
            f.write(ip + '\n')
            f.write('     [Count: ' + count + ']\n')
            f.write('     [Files: {' + files + '}]\n\n')

        f.write('\n Unique Files\n\n')
        for x in top_files:
            file = x[0]
            total_count = str(total_ips['files'][file]['total_count'])
            total_connections = str(total_ips['files'][file]['total_connections'])
            f.write(file + '\n')
            f.write('     [Total Count: ' + total_count + ']\n')
            f.write('     [Total Connections: ' + total_connections + ']\n')
            for x in total_ips['files'][file]['connections']:
                con = total_ips['files'][file]['connections'][x]
                source_ip = con['source_ip']
                destination_ip = str(con['destination_ip'])
                connection_count = str(con['source_ip'])
                f.write('          [Source IP: ' + source_ip + ']\n')
                f.write('          [Destination IP: ' + destination_ip + ']\n')
                f.write('          [Connection Count: ' + connection_count + ']\n')
            f.write('\n')

        f.close()

    print('Export Complete')


def file_discovery_print_output(packets):
    total_ips = packets
    just_ips = total_ips['ips']
    top_total = sorted(just_ips.items(), key=lambda x: x[1]['total_count'], reverse=True)
    just_files = total_ips['files']
    top_files = sorted(just_files.items(), key=lambda x: x[1]['total_count'], reverse=True)

    ip_count = len(top_total)
    file_count = len(top_files)

    print('SMB2 Traffic\n')
    print('Total IP Count: ' + str(ip_count))
    print('Total File Count: ' + str(file_count) + '\n')
    print('Unique IPs\n')
    ip_count = len(top_total)

    if ip_count < 10:
        ip_print = ip_count
    else:
        ip_print = 10

    for x in top_total[:ip_print]:
        ip = x[0]
        count = str(total_ips['ips'][ip]['total_count'])
        files = str(total_ips['ips'][ip]['files'])
        print(ip)
        print('     [Count: ' + count + ']')
        print('     [Files: {' + files + '}]\n')

    print('\nUnique Files')

    files_count = len(top_files)

    if files_count < 10:
        files_print = files_count
    else:
        files_print = 10

    for x in top_files[:files_print]:
        file = x[0]
        total_count = str(total_ips['files'][file]['total_count'])
        total_connections = str(total_ips['files'][file]['total_connections'])
        print(file)
        print('     [Total Count: ' + total_count + ']')
        print('     [Total Connections: ' + total_connections + ']')
        for x in total_ips['files'][file]['connections']:
            con = total_ips['files'][file]['connections'][x]
            source_ip = con['source_ip']
            destination_ip = str(con['destination_ip'])
            connection_count = str(con['source_ip'])
            print('          [Source IP: ' + source_ip + ']')
            print('          [Destination IP: ' + destination_ip + ']')
            print('          [Connection Count: ' + connection_count + ']')
        print('\n')


def file_discovery_json_output(packets,filename):
    ip_count = len(packets['ips'])
    file_count = len(packets['files'])

    print('Total IP Count: ' + str(ip_count) + '\n')
    print('Total File Count: ' + str(file_count) + '\n\n')
    print('Exporting data to ' + filename)
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(packets, f, ensure_ascii=False, indent=4)

    print('Export Complete')


def stats_txt_output(stats,filename):

    print('Exporting data to ' + filename)
    packets = stats

    with open(filename, 'w') as f:
        f.write('Total Packets : ' + str(packets['statistics']['total_packets']) + '\n')
        f.write('Total IPs : ' + str(packets['statistics']['total_ips']) + '\n')
        f.write('Total Source IPs : ' + str(packets['statistics']['total_source_ips']) + '\n')
        f.write('Total Destination IPs : ' + str(packets['statistics']['total_destination_ips']) + '\n')
        f.write('Total Potential Names : ' + str(packets['statistics']['total_potential_names']) + '\n')
        f.write('\n\n')
        f.write('Individual IP Statistics \n\n')

        for x in packets['ips']:

            ip = x
            names = packets['ips'][x]['name']
            source_count = packets['ips'][x]['source_count']
            destination_count = packets['ips'][x]['destination_count']
            region = packets['ips'][x]['region']
            country = packets['ips'][x]['country']

            if region == 'Private IP':

                try:
                    name = str(names[0])
                    name = name.split('.local')[0]
                    f.write(name + '\n')
                    f.write('     IP: ' + ip + '\n')
                    f.write('     Potential Names: ' + str(names) + '\n')
                    f.write('     Source Count: ' + str(source_count) + '\n')
                    f.write('     Destination Count: ' + str(destination_count) + '\n')
                    f.write('     Location: Private IP Address' + '\n')

                except:
                    f.write(ip + '\n')
                    f.write('     ' + ip + '\n')
                    f.write('     IP: ' + ip + '\n')
                    f.write('     Potential Names: ' + str(names) + '\n')
                    f.write('     Source Count: ' + str(source_count) + '\n')
                    f.write('     Destination Count: ' + str(destination_count) + '\n')
                    f.write('     Location: Private IP Address' + '\n')

            else:

                try:
                    name = str(names[0])
                    name = name.split('.local')[0]
                    f.write(name + '\n')
                    f.write('     IP: ' + ip + '\n')
                    f.write('     Potential Names: ' + str(names) + '\n')
                    f.write('     Source Count: ' + str(source_count) + '\n')
                    f.write('     Destination Count: ' + str(destination_count) + '\n')
                    f.write('     Location: ' + str(region) + ', ' + str(country) + '\n')

                except:
                    f.write(ip + '\n')
                    f.write('     ' + ip + '\n')
                    f.write('     IP: ' + ip + '\n')
                    f.write('     Potential Names: ' + str(names) + '\n')
                    f.write('     Source Count: ' + str(source_count) + '\n')
                    f.write('     Destination Count: ' + str(destination_count) + '\n')
                    f.write('     Location: ' + str(region) + ', ' + str(country) + '\n')

            f.write('     Connections (' + str(len(packets['ips'][x]['connections'])) + ')\n')

            for connection in packets['ips'][x]['connections']:
                connection_ip = connection
                connection_source = packets['ips'][x]['connections'][connection]['source_count']
                connection_destination = packets['ips'][x]['connections'][connection]['destination_count']
                f.write('     * ' + connection_ip + ': {Source: ' + str(connection_source) + ', Destination: ' +
                        str(connection_destination) + '}\n')
            f.write('\n')

def streamlit_export_txt(packets):

    full_str = []

    full_str.append('Total Packets : ' + str(packets['statistics']['total_packets']) + '\n')
    full_str.append('Total IPs : ' + str(packets['statistics']['total_ips']) + '\n')
    full_str.append('Total Source IPs : ' + str(packets['statistics']['total_source_ips']) + '\n')
    full_str.append('Total Destination IPs : ' + str(packets['statistics']['total_destination_ips']) + '\n')
    full_str.append('Total Potential Names : ' + str(packets['statistics']['total_potential_names']) + '\n')
    full_str.append('\n\n')
    full_str.append('Individual IP Statistics \n\n')

    for x in packets['ips']:

        ip = x
        names = packets['ips'][x]['name']
        source_count = packets['ips'][x]['source_count']
        destination_count = packets['ips'][x]['destination_count']
        region = packets['ips'][x]['region']
        country = packets['ips'][x]['country']

        if region == 'Private IP':

            try:
                name = str(names[0])
                name = name.split('.local')[0]
                full_str.append(name + '\n')
                full_str.append('     IP: ' + ip + '\n')
                full_str.append('     Potential Names: ' + str(names) + '\n')
                full_str.append('     Source Count: ' + str(source_count) + '\n')
                full_str.append('     Destination Count: ' + str(destination_count) + '\n')
                full_str.append('     Location: Private IP Address' + '\n')

            except:
                full_str.append(ip + '\n')
                full_str.append('     ' + ip + '\n')
                full_str.append('     IP: ' + ip + '\n')
                full_str.append('     Potential Names: ' + str(names) + '\n')
                full_str.append('     Source Count: ' + str(source_count) + '\n')
                full_str.append('     Destination Count: ' + str(destination_count) + '\n')
                full_str.append('     Location: Private IP Address' + '\n')

        else:

            try:
                name = str(names[0])
                name = name.split('.local')[0]
                full_str.append(name + '\n')
                full_str.append('     IP: ' + ip + '\n')
                full_str.append('     Potential Names: ' + str(names) + '\n')
                full_str.append('     Source Count: ' + str(source_count) + '\n')
                full_str.append('     Destination Count: ' + str(destination_count) + '\n')
                full_str.append('     Location: ' + str(region) + ', ' + str(country) + '\n')

            except:
                full_str.append(ip + '\n')
                full_str.append('     ' + ip + '\n')
                full_str.append('     IP: ' + ip + '\n')
                full_str.append('     Potential Names: ' + str(names) + '\n')
                full_str.append('     Source Count: ' + str(source_count) + '\n')
                full_str.append('     Destination Count: ' + str(destination_count) + '\n')
                full_str.append('     Location: ' + str(region) + ', ' + str(country) + '\n')

        full_str.append('     Connections (' + str(len(packets['ips'][x]['connections'])) + ')\n')

        for connection in packets['ips'][x]['connections']:
            connection_ip = connection
            connection_source = packets['ips'][x]['connections'][connection]['source_count']
            connection_destination = packets['ips'][x]['connections'][connection]['destination_count']
            full_str.append('     * ' + connection_ip + ': {Source: ' + str(connection_source) + ', Destination: ' +
                            str(connection_destination) + '}\n')
        full_str.append('\n')

    full_report = ''.join(full_str)

    return full_report