"""
AIDE - Automated IAM Detection Engine
Professional Dashboard Application
"""

import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import streamlit as st
import pandas as pd

from config import Priority, VULNERABILITY_TYPES, GEMINI_API_KEY
from collector import AWSCollector, AWSCollectorError, generate_sample_data
from analyzer import PolicyAnalyzer, Finding
from ai_engine import AIRemediationEngine, generate_sample_remediation
from database import get_db_manager, DatabaseManager

# Page configuration
st.set_page_config(
    page_title="AIDE - IAM Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/XploitGh0st/AIDE',
        'Report a bug': 'https://github.com/XploitGh0st/AIDE/issues',
        'About': 'AIDE - Automated IAM Detection Engine\nAI-Powered AWS Security Scanner'
    }
)

# Professional CSS Styling
st.markdown("""
<style>
    /* Import Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');
    
    /* Global Styles */
    * {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    .stApp {
        background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 50%, #0f0f1a 100%);
        background-attachment: fixed;
    }
    
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    /* Custom scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    ::-webkit-scrollbar-track {
        background: #1a1a2e;
    }
    ::-webkit-scrollbar-thumb {
        background: #3a3a5e;
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #4a4a7e;
    }
    
    /* Header Section */
    .header-container {
        background: linear-gradient(135deg, rgba(0, 212, 255, 0.1) 0%, rgba(0, 153, 204, 0.05) 100%);
        border: 1px solid rgba(0, 212, 255, 0.2);
        border-radius: 16px;
        padding: 2rem 2.5rem;
        margin-bottom: 2rem;
        position: relative;
        overflow: hidden;
    }
    
    .header-container::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
        background: linear-gradient(90deg, #00d4ff, #0099cc, #00d4ff);
        background-size: 200% 100%;
        animation: shimmer 3s linear infinite;
    }
    
    @keyframes shimmer {
        0% { background-position: -200% 0; }
        100% { background-position: 200% 0; }
    }
    
    .logo-section {
        display: flex;
        align-items: center;
        gap: 1rem;
        margin-bottom: 0.5rem;
    }
    
    .logo-icon {
        font-size: 2.5rem;
        filter: drop-shadow(0 0 10px rgba(0, 212, 255, 0.5));
    }
    
    .logo-text {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(135deg, #00d4ff 0%, #ffffff 50%, #00d4ff 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        letter-spacing: -0.5px;
    }
    
    .tagline {
        color: #8b8b9e;
        font-size: 1rem;
        font-weight: 400;
        margin-left: 0.5rem;
    }
    
    .account-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        background: rgba(0, 212, 255, 0.1);
        border: 1px solid rgba(0, 212, 255, 0.3);
        border-radius: 8px;
        padding: 0.5rem 1rem;
        font-size: 0.85rem;
        color: #00d4ff;
        margin-top: 1rem;
    }
    
    .account-badge .dot {
        width: 8px;
        height: 8px;
        background: #00ff88;
        border-radius: 50%;
        animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.5; transform: scale(1.2); }
    }
    
    /* Metric Cards */
    .metrics-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 1.5rem;
        margin-bottom: 2rem;
    }
    
    .metric-card {
        background: linear-gradient(145deg, #1e1e32 0%, #16162a 100%);
        border: 1px solid #2a2a4e;
        border-radius: 16px;
        padding: 1.5rem;
        position: relative;
        overflow: hidden;
        transition: all 0.3s ease;
    }
    
    .metric-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
    }
    
    .metric-card::after {
        content: '';
        position: absolute;
        top: 0;
        right: 0;
        width: 100px;
        height: 100px;
        border-radius: 50%;
        filter: blur(40px);
        opacity: 0.15;
    }
    
    .metric-card.critical::after { background: #ff4757; }
    .metric-card.high::after { background: #ffa502; }
    .metric-card.medium::after { background: #2ed573; }
    .metric-card.total::after { background: #00d4ff; }
    
    .metric-card .icon {
        font-size: 1.5rem;
        margin-bottom: 0.75rem;
        display: block;
    }
    
    .metric-card .value {
        font-size: 2.5rem;
        font-weight: 700;
        margin-bottom: 0.25rem;
        line-height: 1;
    }
    
    .metric-card.critical .value { color: #ff4757; }
    .metric-card.high .value { color: #ffa502; }
    .metric-card.medium .value { color: #2ed573; }
    .metric-card.total .value { color: #00d4ff; }
    
    .metric-card .label {
        color: #8b8b9e;
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: 500;
    }
    
    /* Section Headers */
    .section-header {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        margin-bottom: 1.5rem;
        padding-bottom: 0.75rem;
        border-bottom: 1px solid #2a2a4e;
    }
    
    .section-header h2 {
        color: #ffffff;
        font-size: 1.25rem;
        font-weight: 600;
        margin: 0;
    }
    
    .section-header .count {
        background: rgba(0, 212, 255, 0.15);
        color: #00d4ff;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    
    /* Finding Cards */
    .finding-card {
        background: linear-gradient(145deg, #1e1e32 0%, #18182c 100%);
        border: 1px solid #2a2a4e;
        border-radius: 12px;
        padding: 1.25rem 1.5rem;
        margin-bottom: 0.75rem;
        transition: all 0.2s ease;
        cursor: pointer;
        position: relative;
        overflow: hidden;
    }
    
    .finding-card:hover {
        border-color: #3a3a5e;
        background: linear-gradient(145deg, #242440 0%, #1c1c34 100%);
    }
    
    .finding-card::before {
        content: '';
        position: absolute;
        left: 0;
        top: 0;
        bottom: 0;
        width: 4px;
    }
    
    .finding-card.critical::before { background: linear-gradient(180deg, #ff4757, #ff6b7a); }
    .finding-card.high::before { background: linear-gradient(180deg, #ffa502, #ffbe33); }
    .finding-card.medium::before { background: linear-gradient(180deg, #2ed573, #54e38e); }
    
    .finding-header {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        margin-bottom: 0.75rem;
    }
    
    .finding-title {
        color: #ffffff;
        font-size: 1rem;
        font-weight: 600;
        margin: 0;
        flex: 1;
    }
    
    .priority-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
        padding: 0.3rem 0.75rem;
        border-radius: 6px;
        font-size: 0.7rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .priority-badge.critical {
        background: rgba(255, 71, 87, 0.15);
        color: #ff4757;
        border: 1px solid rgba(255, 71, 87, 0.3);
    }
    
    .priority-badge.high {
        background: rgba(255, 165, 2, 0.15);
        color: #ffa502;
        border: 1px solid rgba(255, 165, 2, 0.3);
    }
    
    .priority-badge.medium {
        background: rgba(46, 213, 115, 0.15);
        color: #2ed573;
        border: 1px solid rgba(46, 213, 115, 0.3);
    }
    
    .finding-meta {
        display: flex;
        gap: 1.5rem;
        color: #6b6b7e;
        font-size: 0.85rem;
    }
    
    .finding-meta span {
        display: flex;
        align-items: center;
        gap: 0.35rem;
    }
    
    /* Action Buttons */
    .action-button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 0.5rem;
        padding: 0.75rem 1.5rem;
        border-radius: 10px;
        font-size: 0.9rem;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s ease;
        border: none;
        text-decoration: none;
    }
    
    .action-button.primary {
        background: linear-gradient(135deg, #00d4ff 0%, #0099cc 100%);
        color: white;
        box-shadow: 0 4px 15px rgba(0, 212, 255, 0.3);
    }
    
    .action-button.primary:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 25px rgba(0, 212, 255, 0.4);
    }
    
    .action-button.secondary {
        background: rgba(255, 255, 255, 0.05);
        color: #ffffff;
        border: 1px solid #3a3a5e;
    }
    
    .action-button.secondary:hover {
        background: rgba(255, 255, 255, 0.1);
        border-color: #4a4a6e;
    }
    
    /* Remediation Panel */
    .remediation-panel {
        background: linear-gradient(145deg, #1e1e32 0%, #16162a 100%);
        border: 1px solid #2a2a4e;
        border-radius: 16px;
        padding: 2rem;
        margin-top: 1.5rem;
    }
    
    .remediation-header {
        display: flex;
        align-items: center;
        gap: 1rem;
        margin-bottom: 1.5rem;
        padding-bottom: 1rem;
        border-bottom: 1px solid #2a2a4e;
    }
    
    .remediation-header .icon {
        font-size: 2rem;
        filter: drop-shadow(0 0 10px rgba(0, 212, 255, 0.5));
    }
    
    .remediation-header h3 {
        color: #ffffff;
        font-size: 1.25rem;
        font-weight: 600;
        margin: 0;
    }
    
    .remediation-header p {
        color: #6b6b7e;
        font-size: 0.9rem;
        margin: 0.25rem 0 0 0;
    }
    
    /* Code Blocks */
    .code-container {
        background: #0d0d1a;
        border: 1px solid #2a2a4e;
        border-radius: 12px;
        overflow: hidden;
    }
    
    .code-header {
        background: #16162a;
        padding: 0.75rem 1rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 1px solid #2a2a4e;
    }
    
    .code-header .label {
        color: #8b8b9e;
        font-size: 0.8rem;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .code-body {
        padding: 1rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
        line-height: 1.6;
        overflow-x: auto;
    }
    
    /* Status Messages */
    .status-success {
        background: rgba(46, 213, 115, 0.1);
        border: 1px solid rgba(46, 213, 115, 0.3);
        border-radius: 10px;
        padding: 1rem 1.25rem;
        color: #2ed573;
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }
    
    .status-warning {
        background: rgba(255, 165, 2, 0.1);
        border: 1px solid rgba(255, 165, 2, 0.3);
        border-radius: 10px;
        padding: 1rem 1.25rem;
        color: #ffa502;
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }
    
    .status-error {
        background: rgba(255, 71, 87, 0.1);
        border: 1px solid rgba(255, 71, 87, 0.3);
        border-radius: 10px;
        padding: 1rem 1.25rem;
        color: #ff4757;
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }
    
    .status-info {
        background: rgba(0, 212, 255, 0.1);
        border: 1px solid rgba(0, 212, 255, 0.3);
        border-radius: 10px;
        padding: 1rem 1.25rem;
        color: #00d4ff;
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #12121f 0%, #0f0f1a 100%);
        border-right: 1px solid #2a2a4e;
    }
    
    section[data-testid="stSidebar"] .block-container {
        padding-top: 2rem;
    }
    
    .sidebar-section {
        background: rgba(255, 255, 255, 0.02);
        border: 1px solid #2a2a4e;
        border-radius: 12px;
        padding: 1.25rem;
        margin-bottom: 1rem;
    }
    
    .sidebar-section h4 {
        color: #ffffff;
        font-size: 0.85rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    /* Empty State */
    .empty-state {
        text-align: center;
        padding: 4rem 2rem;
    }
    
    .empty-state .icon {
        font-size: 4rem;
        margin-bottom: 1.5rem;
        filter: drop-shadow(0 0 20px rgba(0, 212, 255, 0.3));
    }
    
    .empty-state h3 {
        color: #ffffff;
        font-size: 1.5rem;
        font-weight: 600;
        margin-bottom: 0.75rem;
    }
    
    .empty-state p {
        color: #6b6b7e;
        font-size: 1rem;
        max-width: 500px;
        margin: 0 auto 2rem auto;
        line-height: 1.6;
    }
    
    /* Comparison View */
    .comparison-container {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 1.5rem;
        margin-top: 1.5rem;
    }
    
    .comparison-panel {
        background: #0d0d1a;
        border: 1px solid #2a2a4e;
        border-radius: 12px;
        overflow: hidden;
    }
    
    .comparison-panel.original {
        border-color: rgba(255, 71, 87, 0.3);
    }
    
    .comparison-panel.fixed {
        border-color: rgba(46, 213, 115, 0.3);
    }
    
    .comparison-header {
        padding: 0.75rem 1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-size: 0.85rem;
        font-weight: 600;
    }
    
    .comparison-panel.original .comparison-header {
        background: rgba(255, 71, 87, 0.1);
        color: #ff4757;
        border-bottom: 1px solid rgba(255, 71, 87, 0.2);
    }
    
    .comparison-panel.fixed .comparison-header {
        background: rgba(46, 213, 115, 0.1);
        color: #2ed573;
        border-bottom: 1px solid rgba(46, 213, 115, 0.2);
    }
    
    /* Tab Styling */
    .stTabs [data-baseweb="tab-list"] {
        background: transparent;
        gap: 0.5rem;
        padding: 0;
    }
    
    .stTabs [data-baseweb="tab"] {
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid #2a2a4e;
        border-radius: 8px;
        color: #8b8b9e;
        padding: 0.5rem 1rem;
        font-weight: 500;
    }
    
    .stTabs [aria-selected="true"] {
        background: rgba(0, 212, 255, 0.1);
        border-color: rgba(0, 212, 255, 0.3);
        color: #00d4ff;
    }
    
    .stTabs [data-baseweb="tab-panel"] {
        padding-top: 1.5rem;
    }
    
    /* Scan History */
    .history-item {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 1rem 1.25rem;
        background: rgba(255, 255, 255, 0.02);
        border: 1px solid #2a2a4e;
        border-radius: 10px;
        margin-bottom: 0.5rem;
        transition: all 0.2s ease;
    }
    
    .history-item:hover {
        background: rgba(255, 255, 255, 0.04);
        border-color: #3a3a5e;
    }
    
    .history-info {
        display: flex;
        align-items: center;
        gap: 1rem;
    }
    
    .history-info .id {
        color: #00d4ff;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
    }
    
    .history-info .date {
        color: #6b6b7e;
        font-size: 0.85rem;
    }
    
    .history-stats {
        display: flex;
        gap: 1rem;
        font-size: 0.85rem;
    }
    
    .history-stats .critical { color: #ff4757; }
    .history-stats .high { color: #ffa502; }
    .history-stats .medium { color: #2ed573; }
    
    /* Animation for loading */
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    
    .loading-spinner {
        animation: spin 1s linear infinite;
        display: inline-block;
    }
    
    /* Responsive adjustments */
    @media (max-width: 768px) {
        .metrics-grid {
            grid-template-columns: repeat(2, 1fr);
        }
        .comparison-container {
            grid-template-columns: 1fr;
        }
    }
    
    /* Streamlit Overrides */
    .stButton > button {
        background: linear-gradient(135deg, #00d4ff 0%, #0099cc 100%);
        color: white;
        border: none;
        border-radius: 10px;
        padding: 0.6rem 1.25rem;
        font-weight: 600;
        font-size: 0.9rem;
        transition: all 0.2s ease;
        box-shadow: 0 4px 15px rgba(0, 212, 255, 0.25);
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 25px rgba(0, 212, 255, 0.35);
    }
    
    .stButton > button:active {
        transform: translateY(0);
    }
    
    .stDownloadButton > button {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid #3a3a5e;
        color: white;
    }
    
    .stDownloadButton > button:hover {
        background: rgba(255, 255, 255, 0.1);
        border-color: #4a4a6e;
    }
    
    div[data-testid="stExpander"] {
        background: linear-gradient(145deg, #1e1e32 0%, #18182c 100%);
        border: 1px solid #2a2a4e;
        border-radius: 12px;
        overflow: hidden;
    }
    
    div[data-testid="stExpander"] summary {
        padding: 1rem 1.25rem;
    }
    
    .stSelectbox > div > div {
        background: #1e1e32;
        border-color: #2a2a4e;
    }
    
    .stMultiSelect > div > div {
        background: #1e1e32;
        border-color: #2a2a4e;
    }
    
    .stCheckbox label {
        color: #ffffff;
    }
    
    .stProgress > div > div {
        background: linear-gradient(90deg, #00d4ff, #0099cc);
    }
</style>
""", unsafe_allow_html=True)


def init_session_state():
    """Initialize session state variables."""
    if 'db_manager' not in st.session_state:
        st.session_state.db_manager = get_db_manager()
    if 'current_scan_id' not in st.session_state:
        st.session_state.current_scan_id = None
    if 'findings' not in st.session_state:
        st.session_state.findings = []
    if 'aws_data' not in st.session_state:
        st.session_state.aws_data = None
    if 'selected_finding' not in st.session_state:
        st.session_state.selected_finding = None
    if 'ai_engine' not in st.session_state:
        st.session_state.ai_engine = AIRemediationEngine()
    if 'demo_mode' not in st.session_state:
        st.session_state.demo_mode = False
    if 'scan_running' not in st.session_state:
        st.session_state.scan_running = False


def render_header():
    """Render the professional header."""
    account_info = ""
    if st.session_state.aws_data:
        account_id = st.session_state.aws_data.get('account_id', 'Unknown')
        account_info = f"""
        <div class="account-badge">
            <span class="dot"></span>
            Connected to AWS Account: {account_id}
        </div>
        """
    
    st.markdown(f"""
    <div class="header-container">
        <div class="logo-section">
            <span class="logo-icon">🛡️</span>
            <span class="logo-text">AIDE</span>
            <span class="tagline">Automated IAM Detection Engine</span>
        </div>
        {account_info}
    </div>
    """, unsafe_allow_html=True)


def render_metrics(findings: List[Dict]):
    """Render the metrics cards."""
    critical = len([f for f in findings if f.get('priority') == Priority.CRITICAL])
    high = len([f for f in findings if f.get('priority') == Priority.HIGH])
    medium = len([f for f in findings if f.get('priority') == Priority.MEDIUM])
    total = len(findings)
    
    st.markdown(f"""
    <div class="metrics-grid">
        <div class="metric-card critical">
            <span class="icon">🔴</span>
            <div class="value">{critical}</div>
            <div class="label">Critical Risks</div>
        </div>
        <div class="metric-card high">
            <span class="icon">🟠</span>
            <div class="value">{high}</div>
            <div class="label">High Risks</div>
        </div>
        <div class="metric-card medium">
            <span class="icon">🟢</span>
            <div class="value">{medium}</div>
            <div class="label">Medium Risks</div>
        </div>
        <div class="metric-card total">
            <span class="icon">📊</span>
            <div class="value">{total}</div>
            <div class="label">Total Findings</div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_findings_table(findings: List[Dict]):
    """Render the findings list."""
    if not findings:
        return
    
    # Sort by priority
    priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
    sorted_findings = sorted(findings, key=lambda x: priority_order.get(x.get('priority', 'MEDIUM'), 2))
    
    st.markdown(f"""
    <div class="section-header">
        <h2>🔍 Security Findings</h2>
        <span class="count">{len(findings)} issues</span>
    </div>
    """, unsafe_allow_html=True)
    
    # Filter controls
    col1, col2, col3 = st.columns([2, 2, 6])
    with col1:
        priority_filter = st.multiselect(
            "Priority",
            options=['CRITICAL', 'HIGH', 'MEDIUM'],
            default=['CRITICAL', 'HIGH', 'MEDIUM'],
            label_visibility="collapsed"
        )
    with col2:
        vuln_types = list(set(f.get('vulnerability_type', '') for f in findings))
        type_filter = st.multiselect(
            "Type",
            options=vuln_types,
            default=vuln_types,
            label_visibility="collapsed"
        )
    
    # Filter findings
    filtered = [f for f in sorted_findings 
                if f.get('priority') in priority_filter 
                and f.get('vulnerability_type') in type_filter]
    
    # Render finding cards
    for i, finding in enumerate(filtered):
        priority = finding.get('priority', 'MEDIUM').lower()
        
        with st.expander(f"**{finding.get('title')}** — {finding.get('resource_name')}", expanded=False):
            col1, col2 = st.columns([4, 1])
            
            with col1:
                st.markdown(f"""
                <div style="margin-bottom: 1rem;">
                    <span class="priority-badge {priority}">● {finding.get('priority')}</span>
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown(f"**Resource Type:** {finding.get('resource_type')}")
                st.markdown(f"**Resource ARN:** `{finding.get('resource_arn', 'N/A')}`")
                st.markdown(f"**Description:** {finding.get('description', 'N/A')}")
                
                if finding.get('recommendation'):
                    st.markdown(f"**💡 Recommendation:** {finding.get('recommendation')}")
                
                if finding.get('details'):
                    with st.expander("View Details", expanded=False):
                        st.json(finding.get('details'))
                
                if finding.get('affected_policy'):
                    with st.expander("View Policy JSON", expanded=False):
                        st.code(json.dumps(finding.get('affected_policy'), indent=2), language='json')
            
            with col2:
                if st.button("🔧 Fix", key=f"fix_{i}", use_container_width=True):
                    st.session_state.selected_finding = finding
                    st.rerun()


def render_remediation_panel(finding: Dict):
    """Render the AI remediation panel."""
    st.markdown("""
    <div class="remediation-panel">
        <div class="remediation-header">
            <span class="icon">🤖</span>
            <div>
                <h3>AI-Powered Remediation</h3>
                <p>Generating secure policy fix with Terraform and CLI commands</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Show finding info
    priority = finding.get('priority', 'MEDIUM').lower()
    st.markdown(f"""
    <div class="finding-card {priority}" style="margin: 1rem 0;">
        <div class="finding-header">
            <h4 class="finding-title">{finding.get('title')}</h4>
            <span class="priority-badge {priority}">● {finding.get('priority')}</span>
        </div>
        <div class="finding-meta">
            <span>📦 {finding.get('resource_type')}</span>
            <span>🏷️ {finding.get('resource_name')}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Back button
    if st.button("← Back to Findings", key="back_btn"):
        st.session_state.selected_finding = None
        st.rerun()
    
    if not finding.get('affected_policy'):
        st.markdown("""
        <div class="status-warning">
            <span>⚠️</span>
            <span>No policy document available for this finding. Manual remediation required.</span>
        </div>
        """, unsafe_allow_html=True)
        return
    
    # Generate remediation
    with st.spinner("🔄 Generating AI remediation..."):
        if GEMINI_API_KEY and GEMINI_API_KEY != 'your-gemini-api-key-here':
            engine = st.session_state.ai_engine
            if engine.initialize():
                result = engine.generate_remediation(finding)
            else:
                result = generate_sample_remediation(finding)
        else:
            result = generate_sample_remediation(finding)
    
    if result.success:
        st.markdown("""
        <div class="status-success">
            <span>✅</span>
            <span>Remediation generated successfully!</span>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="status-info">
            <span>ℹ️</span>
            <span>Using sample remediation. Configure Gemini API for full AI features.</span>
        </div>
        """, unsafe_allow_html=True)
    
    # Tabs for different outputs
    tab1, tab2, tab3, tab4 = st.tabs(["📝 Explanation", "📋 Fixed Policy", "🏗️ Terraform", "💻 AWS CLI"])
    
    with tab1:
        st.markdown(result.explanation or "No explanation available.")
    
    with tab2:
        if result.fixed_policy:
            st.code(json.dumps(result.fixed_policy, indent=2), language='json')
            st.download_button(
                "📥 Download Policy",
                json.dumps(result.fixed_policy, indent=2),
                f"fixed_policy_{finding.get('resource_name', 'policy')}.json",
                "application/json"
            )
    
    with tab3:
        if result.terraform_snippet:
            st.code(result.terraform_snippet, language='hcl')
            st.download_button(
                "📥 Download Terraform",
                result.terraform_snippet,
                f"fix_{finding.get('resource_name', 'resource')}.tf",
                "text/plain"
            )
    
    with tab4:
        if result.cli_commands:
            st.code(result.cli_commands, language='bash')
            st.download_button(
                "📥 Download CLI Script",
                result.cli_commands,
                f"fix_{finding.get('resource_name', 'resource')}.sh",
                "text/plain"
            )
    
    # Comparison view
    st.markdown("### 📊 Before vs After")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class="comparison-panel original">
            <div class="comparison-header">❌ Original (Insecure)</div>
        </div>
        """, unsafe_allow_html=True)
        st.code(json.dumps(finding.get('affected_policy', {}), indent=2), language='json')
    
    with col2:
        st.markdown("""
        <div class="comparison-panel fixed">
            <div class="comparison-header">✅ Fixed (Secure)</div>
        </div>
        """, unsafe_allow_html=True)
        if result.fixed_policy:
            st.code(json.dumps(result.fixed_policy, indent=2), language='json')
        else:
            st.info("Fixed policy not available")


def run_scan(demo_mode: bool = False) -> bool:
    """Run a security scan."""
    scan_id = str(uuid.uuid4())[:8]
    st.session_state.current_scan_id = scan_id
    st.session_state.scan_running = True
    
    progress = st.progress(0)
    status = st.empty()
    
    try:
        if demo_mode:
            status.markdown('<div class="status-info"><span>📊</span><span>Loading sample data...</span></div>', unsafe_allow_html=True)
            progress.progress(30)
            aws_data = generate_sample_data()
        else:
            status.markdown('<div class="status-info"><span>🔌</span><span>Connecting to AWS...</span></div>', unsafe_allow_html=True)
            progress.progress(10)
            collector = AWSCollector()
            
            status.markdown('<div class="status-info"><span>📥</span><span>Collecting IAM data...</span></div>', unsafe_allow_html=True)
            progress.progress(30)
            aws_data = collector.collect_all()
        
        st.session_state.aws_data = aws_data
        
        status.markdown('<div class="status-info"><span>🔬</span><span>Analyzing policies...</span></div>', unsafe_allow_html=True)
        progress.progress(60)
        
        analyzer = PolicyAnalyzer(aws_data)
        findings = analyzer.analyze_all()
        
        status.markdown('<div class="status-info"><span>💾</span><span>Saving results...</span></div>', unsafe_allow_html=True)
        progress.progress(80)
        
        findings_dicts = [f.to_dict() for f in findings]
        st.session_state.findings = findings_dicts
        
        # Save to database
        db = st.session_state.db_manager
        scan = db.create_scan(scan_id, account_id=aws_data.get('account_id'))
        
        for finding_dict in findings_dicts:
            db.add_finding(scan.id, finding_dict)
        
        summary = analyzer.get_summary()
        db.complete_scan(scan_id, {
            'total': summary['total_findings'],
            'CRITICAL': summary['by_priority'].get(Priority.CRITICAL, 0),
            'HIGH': summary['by_priority'].get(Priority.HIGH, 0),
            'MEDIUM': summary['by_priority'].get(Priority.MEDIUM, 0)
        }, errors=aws_data.get('errors', []))
        
        progress.progress(100)
        status.markdown('<div class="status-success"><span>✅</span><span>Scan completed successfully!</span></div>', unsafe_allow_html=True)
        
        st.session_state.scan_running = False
        return True
        
    except AWSCollectorError as e:
        status.markdown(f'<div class="status-error"><span>❌</span><span>AWS Error: {e}</span></div>', unsafe_allow_html=True)
        st.session_state.scan_running = False
        return False
        
    except Exception as e:
        status.markdown(f'<div class="status-error"><span>❌</span><span>Error: {e}</span></div>', unsafe_allow_html=True)
        st.session_state.scan_running = False
        return False


def render_empty_state():
    """Render the empty state when no scans exist."""
    st.markdown("""
    <div class="empty-state">
        <div class="icon">🛡️</div>
        <h3>Welcome to AIDE</h3>
        <p>
            Scan your AWS environment for IAM misconfigurations and get AI-powered 
            remediation with Terraform and CLI commands.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        c1, c2 = st.columns(2)
        with c1:
            if st.button("🚀 Run Scan", use_container_width=True, type="primary"):
                if run_scan(demo_mode=st.session_state.demo_mode):
                    st.rerun()
        with c2:
            if st.button("🎭 Try Demo", use_container_width=True):
                st.session_state.demo_mode = True
                if run_scan(demo_mode=True):
                    st.rerun()


def render_sidebar():
    """Render the sidebar."""
    with st.sidebar:
        st.markdown("""
        <div style="text-align: center; padding: 1rem 0 2rem 0;">
            <span style="font-size: 2rem;">🛡️</span>
            <h2 style="color: #00d4ff; margin: 0.5rem 0 0 0; font-size: 1.5rem;">AIDE</h2>
        </div>
        """, unsafe_allow_html=True)
        
        # Scan Controls
        st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
        st.markdown('<h4>⚡ Scan Controls</h4>', unsafe_allow_html=True)
        
        demo = st.checkbox("Demo Mode", value=st.session_state.demo_mode, 
                          help="Use sample data instead of real AWS")
        st.session_state.demo_mode = demo
        
        if st.button("🚀 New Scan", use_container_width=True, type="primary"):
            if run_scan(demo_mode=st.session_state.demo_mode):
                st.rerun()
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Status
        st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
        st.markdown('<h4>📡 Status</h4>', unsafe_allow_html=True)
        
        # AWS Status
        if st.session_state.aws_data:
            account = st.session_state.aws_data.get('account_id', 'N/A')
            st.markdown(f"""
            <div style="display: flex; align-items: center; gap: 0.5rem; color: #2ed573;">
                <span style="font-size: 0.75rem;">●</span>
                <span style="font-size: 0.85rem;">AWS: {account}</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="display: flex; align-items: center; gap: 0.5rem; color: #6b6b7e;">
                <span style="font-size: 0.75rem;">○</span>
                <span style="font-size: 0.85rem;">AWS: Not connected</span>
            </div>
            """, unsafe_allow_html=True)
        
        # AI Status
        ai_configured = GEMINI_API_KEY and GEMINI_API_KEY != 'your-gemini-api-key-here'
        if ai_configured:
            st.markdown("""
            <div style="display: flex; align-items: center; gap: 0.5rem; color: #2ed573; margin-top: 0.5rem;">
                <span style="font-size: 0.75rem;">●</span>
                <span style="font-size: 0.85rem;">AI: Configured</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="display: flex; align-items: center; gap: 0.5rem; color: #ffa502; margin-top: 0.5rem;">
                <span style="font-size: 0.75rem;">○</span>
                <span style="font-size: 0.85rem;">AI: Sample Mode</span>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Statistics
        if st.session_state.findings:
            st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
            st.markdown('<h4>📊 Current Scan</h4>', unsafe_allow_html=True)
            
            findings = st.session_state.findings
            critical = len([f for f in findings if f.get('priority') == 'CRITICAL'])
            high = len([f for f in findings if f.get('priority') == 'HIGH'])
            medium = len([f for f in findings if f.get('priority') == 'MEDIUM'])
            
            st.markdown(f"""
            <div style="font-size: 0.9rem;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                    <span style="color: #ff4757;">Critical</span>
                    <span style="color: #ff4757; font-weight: 600;">{critical}</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                    <span style="color: #ffa502;">High</span>
                    <span style="color: #ffa502; font-weight: 600;">{high}</span>
                </div>
                <div style="display: flex; justify-content: space-between;">
                    <span style="color: #2ed573;">Medium</span>
                    <span style="color: #2ed573; font-weight: 600;">{medium}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown('</div>', unsafe_allow_html=True)
        
        # Detection Rules
        st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
        st.markdown('<h4>🔍 Detection Rules</h4>', unsafe_allow_html=True)
        
        with st.expander("View all 9 rules", expanded=False):
            for vuln_type, info in VULNERABILITY_TYPES.items():
                color = {'CRITICAL': '#ff4757', 'HIGH': '#ffa502', 'MEDIUM': '#2ed573'}.get(info['priority'], '#6b6b7e')
                st.markdown(f"""
                <div style="margin-bottom: 0.75rem; padding-bottom: 0.75rem; border-bottom: 1px solid #2a2a4e;">
                    <div style="color: {color}; font-size: 0.8rem; font-weight: 600; margin-bottom: 0.25rem;">
                        ● {info['name']}
                    </div>
                    <div style="color: #6b6b7e; font-size: 0.75rem; line-height: 1.4;">
                        {info['description'][:80]}...
                    </div>
                </div>
                """, unsafe_allow_html=True)
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Footer
        st.markdown("""
        <div style="text-align: center; padding-top: 2rem; color: #4a4a6e; font-size: 0.75rem;">
            AIDE v1.0.0<br/>
            Powered by Google Gemini AI
        </div>
        """, unsafe_allow_html=True)


def main():
    """Main application entry point."""
    init_session_state()
    render_sidebar()
    render_header()
    
    # Main content
    if st.session_state.selected_finding:
        render_remediation_panel(st.session_state.selected_finding)
    elif st.session_state.findings:
        render_metrics(st.session_state.findings)
        render_findings_table(st.session_state.findings)
    else:
        render_empty_state()


if __name__ == "__main__":
    main()
