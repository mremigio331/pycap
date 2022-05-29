import streamlit as st
import sys
import os
import pydeck as pdk
import pandas as pd
import plotly.graph_objects as go
import networkx as nx
from alive_progress import alive_bar, config_handler
import traceback

import json

sys.path.append('py_Files')
import pycap_analyzer as analyzer
import pycap_conversion as cap_con
import pycap_outputs as outputs




def home():

    header = st.container()

    global ip_map, link_map

    ip_map, link_map = st.columns(2)

    link_map.markdown("<h2 style='text-align: center; '> IP Links </h2>", unsafe_allow_html=True)

    public_df = pd.DataFrame(columns=['IP', 'Lat', 'Lon'])

    pcap = st.sidebar.file_uploader('pcap file',['pcap'])

    analyze = st.sidebar.button('Analyze PCAP')

    sample = st.sidebar.button('Sample Data')

    if analyze:
        with st.spinner('Converting and Analyzing PCAP'):
            try:
                total_ips = pcap_show(pcap)

                public_df = pd.DataFrame(columns=['IP', 'Lat', 'Lon'])
                private_df = pd.DataFrame(columns=['IP', 'Range'])

                for ip in total_ips['ips']:
                    try:
                        lat = total_ips['ips'][ip]['lat']
                        lon = total_ips['ips'][ip]['lon']
                        new_row = {'IP': ip, 'Lon': lon, 'Lat': lat}
                        public_df = public_df.append(new_row, ignore_index=True)

                    except:
                        if ip[0:3] == '10.':
                            new_row = {'IP': ip, 'Range': '10.0.0.0'}
                            private_df = private_df.append(new_row, ignore_index=True)
                        elif ip[0:4] == '172.':
                            new_row = {'IP': ip, 'Range': '172.0.0.0'}
                            private_df = private_df.append(new_row, ignore_index=True)
                        elif ip[0:4] == '192.':
                            new_row = {'IP': ip, 'Range': '192.0.0.0'}
                            private_df = private_df.append(new_row, ignore_index=True)

            except:
                error = traceback.format_exc()
                if 'NoneType' in error:
                    st.error('Please drag and drop or select a file locally before running Analyze PCAP')
                else:
                    st.error('There was an error analyzing the file. Check and confirm it is a pcap')

    if sample:

        with st.spinner('Loading Sample Data'):
            f = open('Data/pycap_sample.json')
            file_load = json.load(f)

            packet = analyzer.stats(file_load)
            link_chart(packet)

            ip_cleanup(packet)

            public_df = pd.DataFrame(columns=['IP', 'Lat', 'Lon'])
            private_df = pd.DataFrame(columns=['IP', 'Range'])

            for ip in packet['ips']:
                try:
                    lat = packet['ips'][ip]['lat']
                    lon = packet['ips'][ip]['lon']
                    new_row = {'IP': ip, 'Lon': lon, 'Lat': lat}
                    public_df = public_df.append(new_row, ignore_index=True)

                except:
                    if ip[0:3] == '10.':
                        new_row = {'IP': ip, 'Range': '10.0.0.0'}
                        private_df = private_df.append(new_row, ignore_index=True)
                    elif ip[0:4] == '172.':
                        new_row = {'IP': ip, 'Range': '172.0.0.0'}
                        private_df = private_df.append(new_row, ignore_index=True)
                    elif ip[0:4] == '192.':
                        new_row = {'IP': ip, 'Range': '192.0.0.0'}
                        private_df = private_df.append(new_row, ignore_index=True)


    with header:

        ip_map.markdown("<h2 style='text-align: center; '> Public IP Map </h2>", unsafe_allow_html=True)
        ip_map.pydeck_chart(
            pdk.Deck(
                map_style='mapbox://styles/mapbox/dark-v10',
                layers=[
                    pdk.Layer(
                        "HeatmapLayer",
                        public_df,
                        opacity=0.9,
                        get_position=['Lon', 'Lat']
                    ),
                    pdk.Layer(
                        'ScatterplotLayer',
                        public_df,
                        get_position='[Lon, Lat]',
                        pickable=True,
                        opacity=0.8,
                        stroked=True,
                        filled=True,
                        radius_scale=6,
                        radius_min_pixels=5,
                        radius_max_pixels=100,
                        line_width_min_pixels=1,
                        get_fill_color=[0, 128, 0],
                        get_line_color=[0, 0, 0]
                    ),
                ],
                tooltip={"html": "<b>Lon: </b> {Lon} <br /> "
                                 "<b>Lat: </b>{Lat} <br /> "
                                 "<b> City: </b>{City} <br /> "
                                 "<b> Country: </b>{Country}"}
            )
        )


def pcap_show(pcap):

    filepath = 'Data/holding_area/' + pcap.name
    with open(os.path.join(filepath), "wb") as f:
        f.write(pcap.getbuffer())

    packets = cap_con.pcap_to_json(filepath)

    packet = analyzer.stats(packets)
    st.success('PCAP Analyzation Successful')
    link_chart(packet)

    os.remove(filepath)
    ip_cleanup(packet)
    return packet


def ip_cleanup(packets):
    st.title('PCAP Statistics')
    lstats, rstats = st.columns(2)
    lstats.header('Total Packets : ' + str(packets['statistics']['total_packets']))
    lstats.header('Total IPs : ' + str(packets['statistics']['total_ips']))
    lstats.header('Total Source IPs : ' + str(packets['statistics']['total_source_ips']))
    rstats.header('Total Destination IPs : ' + str(packets['statistics']['total_destination_ips']))
    rstats.header('Total Potential Names : ' + str(packets['statistics']['total_potential_names']))

    st.title('Individual IP Statistics')
    left, right = st.columns(2)

    side = 'left'

    for x in packets['ips']:

        if side == 'left':
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
                    left.markdown("<h2 style='text-align: center; '>" + name  + "</h2>", unsafe_allow_html=True)
                    left.write('IP: ' + ip)
                    left.write('Potential Names: ' + str(names))
                    left.write('Source Count: ' + str(source_count))
                    left.write('Destination Count: ' + str(destination_count))
                    left.write('Location: Private IP Address')

                except:
                    left.markdown("<h2 style='text-align: center; '>" + ip + "</h2>", unsafe_allow_html=True)
                    left.write('IP: ' + ip)
                    left.write('Potential Names: ' + str(names))
                    left.write('Source Count: ' + str(source_count))
                    left.write('Destination Count: ' + str(destination_count))
                    left.write('Location: Private IP Address')

            else:

                try:
                    name = str(names[0])
                    name = name.split('.local')[0]
                    left.markdown("<h2 style='text-align: center; '>" + name + "</h2>", unsafe_allow_html=True)
                    left.write('IP: ' + ip)
                    left.write('Potential Names: ' + str(names))
                    left.write('Source Count: ' + str(source_count))
                    left.write('Destination Count: ' + str(destination_count))
                    left.write('Location: ' + str(region) + ', ' + str(country))
                except:
                    left.markdown("<h2 style='text-align: center; '>" + ip + "</h2>", unsafe_allow_html=True)
                    left.write('IP: ' + ip)
                    left.write('Potential Names: ' + str(names))
                    left.write('Source Count: ' + str(source_count))
                    left.write('Destination Count: ' + str(destination_count))
                    left.write('Location: ' + str(region) + ', ' + str(country))

            expander = left.expander('Connections (' + str(len(packets['ips'][x]['connections'])) + ')')

            for connection in packets['ips'][x]['connections']:
                connection_ip = connection
                connection_source = packets['ips'][x]['connections'][connection]['source_count']
                connection_destination = packets['ips'][x]['connections'][connection]['destination_count']
                expander.write(' * ' + connection_ip + ': {Source: ' + str(connection_source) + ', Destination: ' +
                           str(connection_destination) + '}')

            side = 'right'

        elif side == 'right':
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
                    right.markdown("<h2 style='text-align: center; '>" + name + "</h2>",
                                  unsafe_allow_html=True)
                    right.write('IP: ' + ip)
                    right.write('Potential Names: ' + str(names))
                    right.write('Source Count: ' + str(source_count))
                    right.write('Destination Count: ' + str(destination_count))
                    right.write('Location: Private IP Address')
                except:
                    right.markdown("<h2 style='text-align: center; '>" + ip + "</h2>", unsafe_allow_html=True)
                    right.write('IP: ' + ip)
                    right.write('Potential Names: ' + str(names))
                    right.write('Source Count: ' + str(source_count))
                    right.write('Destination Count: ' + str(destination_count))
                    right.write('Location: Private IP Address')

            else:
                try:
                    name = str(names[0])
                    name = name.split('.local')[0]
                    right.markdown("<h2 style='text-align: center; '>" +name + "</h2>", unsafe_allow_html=True)
                    right.write('IP: ' + ip)
                    right.write('Potential Names: ' + str(names))
                    right.write('Source Count: ' + str(source_count))
                    right.write('Destination Count: ' + str(destination_count))
                    right.write('Location: ' + str(region) + ', ' + str(country))
                except:
                    right.markdown("<h2 style='text-align: center; '>" + ip + "</h2>", unsafe_allow_html=True)
                    right.write('IP: ' + ip)
                    right.write('Potential Names: ' + str(names))
                    right.write('Source Count: ' + str(source_count))
                    right.write('Destination Count: ' + str(destination_count))
                    right.write('Location: ' + str(region) + ', ' + str(country))

            expander = right.expander('Connections (' + str(len(packets['ips'][x]['connections'])) + ')')

            for connection in packets['ips'][x]['connections']:
                connection_ip = connection
                connection_source = packets['ips'][x]['connections'][connection]['source_count']
                connection_destination = packets['ips'][x]['connections'][connection]['destination_count']
                expander.write(' * ' + connection_ip + ': {Source: ' + str(connection_source) + ', Destination: ' +
                               str(connection_destination) + '}')

            side = 'left'

    report = outputs.streamlit_export_txt(packets)
    st.sidebar.download_button('Download Report', report, file_name = 'streamlit_report.txt')


def link_chart(packet):
    pcap_connections = []
    private_ips = []
    public_ips = []

    time_bar = len(packet['ips'])
    with alive_bar(time_bar) as bar:
        for x in packet['ips']:
            for con in packet['ips'][x]['connections']:
                try:
                    source_ip = con
                    destination_ip = x
                    current_ips = [source_ip, destination_ip]
                    weight = packet['ips'][x]['connections'][con]['destination_count']

                    if weight > 0:
                        line = {'Source': [source_ip],
                                'Target': [destination_ip],
                                'Type': ['Directed'],
                                'Weight': [weight]}
                        packet_info = pd.DataFrame(line)
                        pcap_connections.append(packet_info)

                    else:
                        pass

                    for ip in current_ips:
                        if packet['ips'][ip]['country'] == 'Private IP':
                            if ip not in private_ips:
                                private_ips.append(ip)
                        else:
                            if ip not in public_ips:
                                public_ips.append(ip)

                except:
                    pass

            bar()

    link_df = pd.concat(pcap_connections, axis = 0, ignore_index = True)

    links = nx.from_pandas_edgelist(link_df,
                                    source = 'Source',
                                    target = 'Target',
                                    edge_attr = 'Weight')

    links_3D = nx.spring_layout(links, dim = 20, seed = 40)

    x_private = []
    y_private = []
    z_private = []
    for x in private_ips:
        x_private.append(links_3D[x][0])
        y_private.append(links_3D[x][1])
        z_private.append(links_3D[x][2])

    x_public = []
    y_public = []
    z_public = []
    for x in public_ips:
        x_public.append(links_3D[x][0])
        y_public.append(links_3D[x][1])
        z_public.append(links_3D[x][2])

    edge_list = links.edges()

    x_edges = []
    y_edges = []
    z_edges = []

    for edge in edge_list:
        x_coords = [links_3D[edge[0]][0], links_3D[edge[1]][0], None]
        x_edges += x_coords

        y_coords = [links_3D[edge[0]][1], links_3D[edge[1]][1], None]
        y_edges += y_coords

        z_coords = [links_3D[edge[0]][2], links_3D[edge[1]][2], None]
        z_edges += z_coords

    trace_edges = go.Scatter3d(name = 'Edges',
                               x = x_edges,
                               y = y_edges,
                               z = z_edges,
                               mode = 'lines',
                               line = dict(color = 'blanchedalmond', width = 7),
                               hoverinfo = 'none')

    public_nodes = go.Scatter3d(name = 'Public IPs',
                                x = x_public,
                                y = y_public,
                                z = z_public,
                                mode = 'markers',
                                marker = dict(symbol = 'circle',
                                              size = 10,
                                              color = 'blue'),
                                text = public_ips,
                                hoverinfo = 'text')

    private_nodes = go.Scatter3d(name = 'Private IPs',
                                 x = x_private,
                                 y = y_private,
                                 z = z_private,
                                 mode = 'markers',
                                 marker = dict(symbol = 'circle',
                                               color = 'orange',
                                               size = 10,
                                               colorscale = 'dense',),
                                 text = private_ips,
                                 hoverinfo = 'text')

    public_degrees = []
    for x in nx.degree(links):
        if x[0] in public_ips:
            new_degree = x[1] * 5
            if new_degree < 10:
                new_degree = 5
            if new_degree > 100:
                new_degree = 100

            public_degrees.append(new_degree)

    private_degrees = []
    for x in nx.degree(links):
        if x[0] in private_ips:
            new_degree = x[1] * 5
            if new_degree < 10:
                new_degree = 5
            if new_degree > 100:
                new_degree = 100
            private_degrees.append(new_degree)

    private_nodes.marker.size = private_degrees
    public_nodes.marker.size = public_degrees

    axis = dict(showbackground = False,
                showline = False,
                zeroline = False,
                showgrid = False,
                showticklabels = False)

    layout = go.Layout(height = 600,
                       showlegend = True,
                       scene = dict(xaxis = dict(axis),
                                  yaxis = dict(axis),
                                  zaxis = dict(axis),
                                  ),
                       margin = dict(t = 100),
                       hovermode = 'closest'
                       )

    data = [trace_edges, public_nodes, private_nodes]
    fig = go.Figure(data = data, layout = layout)

    link_map.plotly_chart(fig, use_container_width = True)

