import sys
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

    ip_count = len(top_total)
    file_count = len(top_files)

    print('Total IP Count: ' + str(ip_count) + '\n')
    print('Total File Count: ' + str(file_count) + '\n\n')
    print('Exporting data to ' + filename)
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(packets, f, ensure_ascii=False, indent=4)

    print('Export Complete')