import streamlit as st
import sys
import os
import pydeck as pdk
import pandas as pd

import traceback

import json

sys.path.append('py_Files')
import pycap_analyzer as analyzer




def home():

    header = st.container()
    #dataset = st.container()

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


        st.title('Public IP Map')
        st.pydeck_chart(
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
                tooltip={"html": "<b>Box: </b> {Box} <br /> "
                                 "<b>Lon: </b> {Lon} <br /> "
                                 "<b>Lat: </b>{Lat} <br /> "
                                 "<b> City: </b>{City} <br /> "
                                 "<b> Country: </b>{Country}"}
            )
        )

def pcap_show(pcap):
    with open(os.path.join(pcap.name), "wb") as f:
        f.write(pcap.getbuffer())

    convert = st.info('Converting pcap')
    convert
    packet = analyzer.stats(pcap.name)
    os.remove(pcap.name)
    ip_cleanup(packet)
    return packet
    convert = None
    convert

def ip_cleanup(packets):
    st.title('PCAP Statistics')
    st.header('Total Packets : ' + str(packets['statistics']['total_packets']))
    st.header('Total IPs : ' + str(packets['statistics']['total_ips']))
    st.header('Total Source IPs : ' + str(packets['statistics']['total_source_ips']))
    st.header('Total Destination IPs : ' + str(packets['statistics']['total_destination_ips']))
    st.header('Total Potential Names : ' + str(packets['statistics']['total_potential_names']))

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
                    left.subheader('IP: ' + ip)
                    left.subheader('Potential Names: ' + str(names))
                    left.subheader('Source Count: ' + str(source_count))
                    left.subheader('Destination Count: ' + str(destination_count))
                    left.subheader('Location: Private IP Address')

                except:
                    left.markdown("<h2 style='text-align: center; '>" + ip + "</h2>", unsafe_allow_html=True)
                    left.subheader('IP: ' + ip)
                    left.subheader('Potential Names: ' + str(names))
                    left.subheader('Source Count: ' + str(source_count))
                    left.subheader('Destination Count: ' + str(destination_count))
                    left.subheader('Location: Private IP Address')

            else:

                try:
                    name = str(names[0])
                    name = name.split('.local')[0]
                    left.markdown("<h2 style='text-align: center; '>" + name + "</h2>", unsafe_allow_html=True)
                    left.subheader('IP: ' + ip)
                    left.subheader('Potential Names: ' + str(names))
                    left.subheader('Source Count: ' + str(source_count))
                    left.subheader('Destination Count: ' + str(destination_count))
                    left.subheader('Location: ' + str(region) + ', ' + str(country))
                except:
                    left.markdown("<h2 style='text-align: center; '>" + ip + "</h2>", unsafe_allow_html=True)
                    left.subheader('IP: ' + ip)
                    left.subheader('Potential Names: ' + str(names))
                    left.subheader('Source Count: ' + str(source_count))
                    left.subheader('Destination Count: ' + str(destination_count))
                    left.subheader('Location: ' + str(region) + ', ' + str(country))

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
                    right.subheader('IP: ' + ip)
                    right.subheader('Potential Names: ' + str(names))
                    right.subheader('Source Count: ' + str(source_count))
                    right.subheader('Destination Count: ' + str(destination_count))
                    right.subheader('Location: Private IP Address')
                except:
                    right.markdown("<h2 style='text-align: center; '>" + ip + "</h2>", unsafe_allow_html=True)
                    right.subheader('IP: ' + ip)
                    right.subheader('Potential Names: ' + str(names))
                    right.subheader('Source Count: ' + str(source_count))
                    right.subheader('Destination Count: ' + str(destination_count))
                    right.subheader('Location: Private IP Address')

            else:
                try:
                    name = str(names[0])
                    name = name.split('.local')[0]
                    right.markdown("<h2 style='text-align: center; '>" +name + "</h2>", unsafe_allow_html=True)
                    right.subheader('IP: ' + ip)
                    right.subheader('Potential Names: ' + str(names))
                    right.subheader('Source Count: ' + str(source_count))
                    right.subheader('Destination Count: ' + str(destination_count))
                    right.subheader('Location: ' + str(region) + ', ' + str(country))
                except:
                    right.markdown("<h2 style='text-align: center; '>" + ip + "</h2>", unsafe_allow_html=True)
                    right.subheader('IP: ' + ip)
                    right.subheader('Potential Names: ' + str(names))
                    right.subheader('Source Count: ' + str(source_count))
                    right.subheader('Destination Count: ' + str(destination_count))
                    right.subheader('Location: ' + str(region) + ', ' + str(country))

            expander = right.expander('Connections (' + str(len(packets['ips'][x]['connections'])) + ')')

            for connection in packets['ips'][x]['connections']:
                connection_ip = connection
                connection_source = packets['ips'][x]['connections'][connection]['source_count']
                connection_destination = packets['ips'][x]['connections'][connection]['destination_count']
                expander.write(' * ' + connection_ip + ': {Source: ' + str(connection_source) + ', Destination: ' +
                               str(connection_destination) + '}')

            side = 'left'