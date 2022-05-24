import streamlit as st
import sys
import os
import pydeck as pdk
import pandas as pd
import plotly.graph_objects as go
import networkx as nx

import traceback

import json

sys.path.append('py_Files')
import pycap_analyzer as analyzer
import pycap_conversion as cap_con
import pycap_gephi as gephi




def home():

    header = st.container()
    #dataset = st.container()
    global ip_map, link_map

    ip_map, link_map = st.columns(2)

    link_map.markdown("<h2 style='text-align: center; '> IP Links </h2>", unsafe_allow_html=True)

    public_df = pd.DataFrame(columns=['IP', 'Lat', 'Lon'])

    pcap = st.sidebar.file_uploader('pcap file',['pcap'])

    analyze = st.sidebar.button('Analyze pcap')

    if analyze:
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



    with header:
        st.title('Home Page')

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

    with open(os.path.join(pcap.name), "wb") as f:
        f.write(pcap.getbuffer())

    packets = cap_con.pcap_to_json(pcap.name)

    packet = analyzer.stats(packets)
    link_df = gephi.cap_to_link_df(packets)

    link_chart(link_df)

    os.remove(pcap.name)
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


def link_chart(link_df):
    links = nx.from_pandas_edgelist(link_df,
                                    source='Source',
                                    target='Target',
                                    edge_attr=True,
                                    create_using=nx.DiGraph()
                                    )

    nodes = []
    for x in links.nodes():
        nodes.append(x)

    links_3D = nx.spring_layout(links, dim=20, seed=40)
    #links_3D = nx.spring_layout(links, k=0.15, iterations=20)


    x_nodes = []
    y_nodes = []
    z_nodes = []
    for x in links_3D:
        x_nodes.append(links_3D[x][0])
        y_nodes.append(links_3D[x][1])
        z_nodes.append(links_3D[x][2])

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

    trace_edges = go.Scatter3d(x=x_edges,
                               y=y_edges,
                               z=z_edges,
                               mode='lines',
                               line=dict(color='black', width=4),
                               hoverinfo='none')

    trace_nodes = go.Scatter3d(x=x_nodes,
                               y=y_nodes,
                               z=z_nodes,
                               mode='markers',
                               marker=dict(symbol='circle',
                                           size=10,
                                           colorscale=['lightgreen', 'magenta'],  # either green or mageneta
                                           line=dict(color='black', width=1)),
                               text=nodes,
                               hoverinfo='text')

    degrees = []
    for x in nx.degree(links):
        new_degree = x[1] * 5
        if new_degree < 10:
            new_degree = 5
        if new_degree > 100:
            new_degree = 100
        degrees.append(new_degree)

    trace_nodes.marker.size = degrees

    axis = dict(showbackground=False,
                showline=False,
                zeroline=False,
                showgrid=False,
                showticklabels=False)

    layout = go.Layout(height = 600,
                       showlegend=False,
                       scene=dict(xaxis=dict(axis),
                                  yaxis=dict(axis),
                                  zaxis=dict(axis),
                                  ),
                       margin=dict(t=100),
                       hovermode='closest'
    )

    data = [trace_edges, trace_nodes]
    fig = go.Figure(data=data, layout=layout)


    link_map.plotly_chart(fig, use_container_width = True)