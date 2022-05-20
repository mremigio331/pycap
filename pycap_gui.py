import streamlit as st
import sys
sys.path.append('GUIs/')
import home_page as home


st.set_page_config(page_title='PyCap', layout='wide', initial_sidebar_state='auto')
page = st.sidebar.selectbox('Page', ['Home'])
st.title('PyCap pcap Analyzer')


if page == 'Home':
    home.home()
