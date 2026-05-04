import streamlit as st
import pandas as pd
from parser import LogParser
from agent import SentinelAgent
import time

# --- Page Config ---
st.set_page_config(
    page_title="SentinelAI | Security Dashboard",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom CSS for "Premium" feel ---
st.markdown("""
<style>
    .reportview-container {
        background: #0e1117;
    }
    .main {
        background: #0e1117;
        color: #e0e0e0;
    }
    .stMetric {
        background-color: #1e2130;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #3e4150;
    }
    .threat-card {
        background-color: #262730;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #ff4b4b;
        margin-bottom: 10px;
    }
</style>
""", unsafe_allow_html=True)

# --- Sidebar ---
st.sidebar.title("SentinelAI Control")
st.sidebar.info("Autonomous Security Analyst v1.0")
uploaded_file = st.sidebar.file_uploader("Upload System Logs (.log)", type="log")

# --- Initialize Agent ---
if 'agent' not in st.session_state:
    st.session_state.agent = SentinelAgent()

if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

# --- Main Dashboard ---
st.title("SentinelAI: Autonomous Threat Monitor")
st.markdown("---")

col1, col2, col3 = st.columns(3)

# Mock stats if no file
if uploaded_file is None:
    col1.metric("System Status", "PROTECTED", delta="Secure")
    col2.metric("Active Threats", "0", delta="0")
    col3.metric("Last Scan", "Never")
    
    st.warning("Please upload a log file to begin autonomous analysis.")
    
    # Show example data button
    if st.button("Load Demo Logs"):
        # We'll simulate loading logs
        demo_logs = [
            "May  3 10:12:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 54321 ssh2",
            "May  3 10:12:05 server sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 54325 ssh2",
            "May  3 10:12:10 server sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 54330 ssh2",
            "127.0.0.1 - - [03/May/2026:10:15:20 +0000] \"GET /admin' OR '1'='1 HTTP/1.1\" 404 154"
        ]
        st.session_state.logs = demo_logs
        st.rerun()

else:
    # Process Uploaded File
    lines = uploaded_file.getvalue().decode("utf-8").splitlines()
    st.session_state.logs = lines

if 'logs' in st.session_state:
    parser = LogParser()
    auth_df = parser.parse_auth_log(st.session_state.logs)
    access_df = parser.parse_access_log(st.session_state.logs)
    
    threats_found = len(auth_df[auth_df['event'] == 'Failed Login']) + len(access_df[access_df['event'] != 'Web Request'])
    
    col1.metric("System Status", "ALERT" if threats_found > 0 else "PROTECTED", delta="- Threat Detected" if threats_found > 0 else "Stable")
    col2.metric("Active Threats", str(threats_found), delta=str(threats_found))
    col3.metric("Last Scan", time.strftime("%H:%M:%S"))

    st.subheader("Structured Log Analysis")
    tab1, tab2 = st.tabs(["Auth Logs (SSH)", "Access Logs (Web)"])
    
    with tab1:
        st.dataframe(auth_df, use_container_width=True)
    with tab2:
        st.dataframe(access_df, use_container_width=True)

    # Autonomous Investigation Section
    st.markdown("---")
    st.subheader("Autonomous AI Investigation")
    
    if st.button("Run SentinelAI Deep Analysis"):
        with st.spinner("Agent is reasoning about detected patterns..."):
            # Prepare context for the agent to avoid rate limits
            suspicious_auth = auth_df[auth_df['event'] == 'Failed Login'].head(50)
            suspicious_access = access_df[access_df['event'] != 'Web Request'].head(50)
            
            if suspicious_auth.empty and suspicious_access.empty:
                context = "System normal. Sample Auth Logs:\n" + auth_df.head(10).to_string() + "\nSample Access Logs:\n" + access_df.head(10).to_string()
            else:
                context = "Suspicious Auth Logs (Max 50):\n" + suspicious_auth.to_string() + "\n\nSuspicious Access Logs (Max 50):\n" + suspicious_access.to_string()
            report = st.session_state.agent.analyze_threat(context)
            
            st.session_state.chat_history.append({"role": "system", "content": report})
            st.success("Analysis Complete. Recommendations generated based on corporate security policy and real-time threat intel.")

st.markdown("---")
st.subheader("Interactive Agent Terminal")
st.markdown("Chat with SentinelAI or ask it to run diagnostic commands (ping, nslookup, netstat) on the server.")

# Display chat history
for message in st.session_state.chat_history:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Chat Input
if prompt := st.chat_input("E.g., 'Ping 192.168.1.50' or 'What is a SQL injection?'"):
    st.session_state.chat_history.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)
        
    with st.chat_message("assistant"):
        with st.spinner("Processing request..."):
            response = st.session_state.agent.chat(prompt)
            st.markdown(response)
    st.session_state.chat_history.append({"role": "assistant", "content": response})

st.markdown("---")
st.caption("Sathush 504 | 2026")
