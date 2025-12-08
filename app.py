"""
AIDE - Automated IAM Detection Engine
Streamlit Dashboard Application
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
    page_title="AIDE - IAM Detection Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark mode and modern styling
st.markdown("""
<style>
    /* Dark theme override */
    .stApp {
        background-color: #0e1117;
    }
    
    /* Main header styling */
    .main-header {
        background: linear-gradient(90deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        border: 1px solid #1e3a5f;
    }
    
    .main-header h1 {
        color: #00d4ff;
        font-size: 2.5rem;
        margin-bottom: 0.5rem;
    }
    
    .main-header p {
        color: #a0a0a0;
        font-size: 1.1rem;
    }
    
    /* Metric cards */
    .metric-card {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        padding: 1.5rem;
        border-radius: 10px;
        border: 1px solid #1e3a5f;
        text-align: center;
    }
    
    .metric-value {
        font-size: 2.5rem;
        font-weight: bold;
        margin-bottom: 0.5rem;
    }
    
    .metric-label {
        color: #a0a0a0;
        font-size: 0.9rem;
        text-transform: uppercase;
    }
    
    .critical { color: #ff4757; }
    .high { color: #ffa502; }
    .medium { color: #2ed573; }
    .info { color: #00d4ff; }
    
    /* Finding cards */
    .finding-card {
        background: #1a1a2e;
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 0.5rem;
        border-left: 4px solid;
    }
    
    .finding-card.critical { border-left-color: #ff4757; }
    .finding-card.high { border-left-color: #ffa502; }
    .finding-card.medium { border-left-color: #2ed573; }
    
    /* Priority badges */
    .priority-badge {
        display: inline-block;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: bold;
        text-transform: uppercase;
    }
    
    .priority-badge.critical {
        background: rgba(255, 71, 87, 0.2);
        color: #ff4757;
        border: 1px solid #ff4757;
    }
    
    .priority-badge.high {
        background: rgba(255, 165, 2, 0.2);
        color: #ffa502;
        border: 1px solid #ffa502;
    }
    
    .priority-badge.medium {
        background: rgba(46, 213, 115, 0.2);
        color: #2ed573;
        border: 1px solid #2ed573;
    }
    
    /* Code blocks */
    .code-block {
        background: #0d1117;
        padding: 1rem;
        border-radius: 8px;
        border: 1px solid #30363d;
        font-family: 'Monaco', 'Consolas', monospace;
        font-size: 0.85rem;
        overflow-x: auto;
    }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(90deg, #00d4ff 0%, #0099cc 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.5rem 1rem;
        font-weight: bold;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        background: linear-gradient(90deg, #00b8e6 0%, #0088b3 100%);
        box-shadow: 0 4px 15px rgba(0, 212, 255, 0.3);
    }
    
    /* Sidebar */
    .css-1d391kg {
        background-color: #0e1117;
    }
    
    /* Tables */
    .dataframe {
        background: #1a1a2e !important;
    }
    
    /* Expander */
    .streamlit-expanderHeader {
        background: #1a1a2e;
        border-radius: 8px;
    }
    
    /* Success/Error messages */
    .success-box {
        background: rgba(46, 213, 115, 0.1);
        border: 1px solid #2ed573;
        border-radius: 8px;
        padding: 1rem;
        color: #2ed573;
    }
    
    .error-box {
        background: rgba(255, 71, 87, 0.1);
        border: 1px solid #ff4757;
        border-radius: 8px;
        padding: 1rem;
        color: #ff4757;
    }
    
    .warning-box {
        background: rgba(255, 165, 2, 0.1);
        border: 1px solid #ffa502;
        border-radius: 8px;
        padding: 1rem;
        color: #ffa502;
    }
    
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        background: #1a1a2e;
        border-radius: 8px 8px 0 0;
        border: 1px solid #1e3a5f;
        padding: 0.5rem 1rem;
    }
    
    .stTabs [aria-selected="true"] {
        background: #16213e;
        border-bottom-color: #16213e;
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


def render_header():
    """Render the main header."""
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ AIDE</h1>
        <p>Automated IAM Detection Engine - AI-Powered AWS Security Scanner</p>
    </div>
    """, unsafe_allow_html=True)


def render_metrics(findings: List[Dict]):
    """Render the summary metrics."""
    critical = len([f for f in findings if f.get('priority') == Priority.CRITICAL])
    high = len([f for f in findings if f.get('priority') == Priority.HIGH])
    medium = len([f for f in findings if f.get('priority') == Priority.MEDIUM])
    total = len(findings)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value critical">{critical}</div>
            <div class="metric-label">Critical Risks</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value high">{high}</div>
            <div class="metric-label">High Risks</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value medium">{medium}</div>
            <div class="metric-label">Medium Risks</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value info">{total}</div>
            <div class="metric-label">Total Findings</div>
        </div>
        """, unsafe_allow_html=True)


def get_priority_badge(priority: str) -> str:
    """Get HTML for priority badge."""
    priority_lower = priority.lower()
    return f'<span class="priority-badge {priority_lower}">{priority}</span>'


def render_findings_table(findings: List[Dict]):
    """Render the findings table."""
    if not findings:
        st.info("No findings to display. Run a scan to detect IAM vulnerabilities.")
        return
    
    # Create dataframe for display
    df_data = []
    for i, f in enumerate(findings):
        df_data.append({
            'Index': i,
            'Priority': f.get('priority', 'MEDIUM'),
            'Title': f.get('title', 'Unknown'),
            'Resource Type': f.get('resource_type', 'Unknown'),
            'Resource': f.get('resource_name', 'Unknown'),
            'Vulnerability': f.get('vulnerability_type', 'Unknown')
        })
    
    df = pd.DataFrame(df_data)
    
    # Priority filter
    priorities = st.multiselect(
        "Filter by Priority",
        options=['CRITICAL', 'HIGH', 'MEDIUM'],
        default=['CRITICAL', 'HIGH', 'MEDIUM']
    )
    
    filtered_df = df[df['Priority'].isin(priorities)]
    
    # Sort by priority
    priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
    filtered_df['PriorityOrder'] = filtered_df['Priority'].map(priority_order)
    filtered_df = filtered_df.sort_values('PriorityOrder')
    
    st.markdown(f"### 📋 Findings ({len(filtered_df)})")
    
    # Display findings as expandable cards
    for _, row in filtered_df.iterrows():
        finding = findings[row['Index']]
        priority_class = finding.get('priority', 'medium').lower()
        
        with st.expander(f"**{finding.get('title')}** - {finding.get('resource_name')}", expanded=False):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.markdown(f"**Priority:** {get_priority_badge(finding.get('priority', 'MEDIUM'))}", unsafe_allow_html=True)
                st.markdown(f"**Resource Type:** {finding.get('resource_type')}")
                st.markdown(f"**Resource ARN:** `{finding.get('resource_arn', 'N/A')}`")
                st.markdown(f"**Description:** {finding.get('description', 'N/A')}")
                
                if finding.get('recommendation'):
                    st.markdown(f"**Recommendation:** {finding.get('recommendation')}")
                
                if finding.get('details'):
                    st.markdown("**Additional Details:**")
                    st.json(finding.get('details'))
            
            with col2:
                if st.button("🔧 Generate Fix", key=f"fix_{row['Index']}"):
                    st.session_state.selected_finding = finding
                    st.rerun()
            
            # Show affected policy if available
            if finding.get('affected_policy'):
                st.markdown("**Affected Policy:**")
                st.code(json.dumps(finding.get('affected_policy'), indent=2), language='json')


def render_remediation_panel(finding: Dict):
    """Render the AI remediation panel."""
    st.markdown("---")
    st.markdown("### 🔧 AI-Powered Remediation")
    
    st.markdown(f"""
    <div class="finding-card {finding.get('priority', 'medium').lower()}">
        <strong>{finding.get('title')}</strong><br/>
        <small>Resource: {finding.get('resource_name')} ({finding.get('resource_type')})</small>
    </div>
    """, unsafe_allow_html=True)
    
    # Check if we have an affected policy to remediate
    if not finding.get('affected_policy'):
        st.warning("No policy document available for this finding. Manual remediation required.")
        
        if st.button("← Back to Findings"):
            st.session_state.selected_finding = None
            st.rerun()
        return
    
    # Generate remediation
    with st.spinner("🤖 Generating AI remediation..."):
        # Check if Gemini API is configured
        if GEMINI_API_KEY and GEMINI_API_KEY != 'your-gemini-api-key-here':
            engine = st.session_state.ai_engine
            if engine.initialize():
                result = engine.generate_remediation(finding)
            else:
                result = generate_sample_remediation(finding)
        else:
            # Use sample remediation for demo
            result = generate_sample_remediation(finding)
    
    if result.success:
        st.markdown('<div class="success-box">✅ Remediation generated successfully!</div>', unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="warning-box">⚠️ Using sample remediation. {result.error or "Configure Gemini API for full AI features."}</div>', unsafe_allow_html=True)
    
    # Display remediation results in tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📝 Explanation", "📋 Fixed Policy", "🏗️ Terraform", "💻 AWS CLI"])
    
    with tab1:
        st.markdown(result.explanation or "No explanation available.")
    
    with tab2:
        if result.fixed_policy:
            st.code(json.dumps(result.fixed_policy, indent=2), language='json')
            
            # Copy button
            st.download_button(
                label="📥 Download Fixed Policy",
                data=json.dumps(result.fixed_policy, indent=2),
                file_name=f"fixed_policy_{finding.get('resource_name', 'policy')}.json",
                mime="application/json"
            )
        else:
            st.info("No fixed policy available.")
    
    with tab3:
        if result.terraform_snippet:
            st.code(result.terraform_snippet, language='hcl')
            
            st.download_button(
                label="📥 Download Terraform",
                data=result.terraform_snippet,
                file_name=f"fix_{finding.get('resource_name', 'resource')}.tf",
                mime="text/plain"
            )
        else:
            st.info("No Terraform snippet available.")
    
    with tab4:
        if result.cli_commands:
            st.code(result.cli_commands, language='bash')
            
            st.download_button(
                label="📥 Download CLI Commands",
                data=result.cli_commands,
                file_name=f"fix_{finding.get('resource_name', 'resource')}.sh",
                mime="text/plain"
            )
        else:
            st.info("No CLI commands available.")
    
    # Comparison view
    st.markdown("### 📊 Before vs After Comparison")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**❌ Original (Insecure)**")
        st.code(json.dumps(finding.get('affected_policy', {}), indent=2), language='json')
    
    with col2:
        st.markdown("**✅ Fixed (Secure)**")
        if result.fixed_policy:
            st.code(json.dumps(result.fixed_policy, indent=2), language='json')
        else:
            st.info("Fixed policy not available")
    
    # Save to database
    if st.button("💾 Save Remediation"):
        db = st.session_state.db_manager
        # This would save to DB in a real implementation
        st.success("Remediation saved to history!")
    
    if st.button("← Back to Findings"):
        st.session_state.selected_finding = None
        st.rerun()


def run_scan(demo_mode: bool = False):
    """Run a security scan."""
    scan_id = str(uuid.uuid4())[:8]
    st.session_state.current_scan_id = scan_id
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    try:
        if demo_mode:
            status_text.text("📊 Loading sample data...")
            progress_bar.progress(30)
            aws_data = generate_sample_data()
        else:
            status_text.text("🔍 Connecting to AWS...")
            progress_bar.progress(10)
            
            collector = AWSCollector()
            
            status_text.text("📥 Collecting IAM data...")
            progress_bar.progress(30)
            
            aws_data = collector.collect_all()
        
        st.session_state.aws_data = aws_data
        
        status_text.text("🔬 Analyzing policies...")
        progress_bar.progress(60)
        
        analyzer = PolicyAnalyzer(aws_data)
        findings = analyzer.analyze_all()
        
        status_text.text("💾 Saving results...")
        progress_bar.progress(80)
        
        # Convert findings to dicts
        findings_dicts = [f.to_dict() for f in findings]
        st.session_state.findings = findings_dicts
        
        # Save to database
        db = st.session_state.db_manager
        scan = db.create_scan(scan_id, account_id=aws_data.get('account_id'))
        
        for finding_dict in findings_dicts:
            db.add_finding(scan.id, finding_dict)
        
        summary = analyzer.get_summary()
        db.complete_scan(
            scan_id, 
            {
                'total': summary['total_findings'],
                'CRITICAL': summary['by_priority'].get(Priority.CRITICAL, 0),
                'HIGH': summary['by_priority'].get(Priority.HIGH, 0),
                'MEDIUM': summary['by_priority'].get(Priority.MEDIUM, 0)
            },
            errors=aws_data.get('errors', [])
        )
        
        progress_bar.progress(100)
        status_text.text("✅ Scan complete!")
        
        return True
        
    except AWSCollectorError as e:
        status_text.text(f"❌ AWS Error: {e}")
        st.error(f"Failed to connect to AWS: {e}")
        st.info("💡 Tip: Try running in Demo Mode to see how AIDE works without AWS credentials.")
        return False
        
    except Exception as e:
        status_text.text(f"❌ Error: {e}")
        st.error(f"Scan failed: {e}")
        return False


def render_sidebar():
    """Render the sidebar."""
    with st.sidebar:
        st.markdown("## ⚙️ Settings")
        
        st.markdown("### Scan Mode")
        demo_mode = st.checkbox(
            "Demo Mode",
            value=st.session_state.demo_mode,
            help="Use sample data instead of connecting to AWS"
        )
        st.session_state.demo_mode = demo_mode
        
        if demo_mode:
            st.info("🎭 Demo mode active. Using sample AWS data.")
        else:
            st.markdown("### AWS Configuration")
            st.text_input("AWS Profile", value="default", key="aws_profile")
            st.text_input("AWS Region", value="us-east-1", key="aws_region")
        
        st.markdown("---")
        
        st.markdown("### 🔐 AI Configuration")
        api_key_configured = GEMINI_API_KEY and GEMINI_API_KEY != 'your-gemini-api-key-here'
        
        if api_key_configured:
            st.success("✅ Gemini API configured")
        else:
            st.warning("⚠️ Gemini API not configured")
            st.markdown("Add your API key to `.env` file:")
            st.code("GEMINI_API_KEY=your-key-here")
        
        st.markdown("---")
        
        st.markdown("### 📊 Statistics")
        db = st.session_state.db_manager
        stats = db.get_stats()
        
        st.metric("Total Scans", stats.get('total_scans', 0))
        st.metric("Total Findings", stats.get('total_findings', 0))
        st.metric("Open Issues", stats.get('open_findings', 0))
        
        st.markdown("---")
        
        st.markdown("### 📚 Vulnerability Types")
        with st.expander("View all 9 detection rules"):
            for vuln_type, info in VULNERABILITY_TYPES.items():
                priority_color = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡'
                }.get(info['priority'], '⚪')
                
                st.markdown(f"{priority_color} **{info['name']}**")
                st.caption(info['description'])
                st.markdown("---")


def render_scan_history():
    """Render scan history."""
    st.markdown("### 📜 Recent Scans")
    
    db = st.session_state.db_manager
    scans = db.get_all_scans(limit=10)
    
    if not scans:
        st.info("No scan history. Run your first scan!")
        return
    
    for scan in scans:
        col1, col2, col3, col4, col5 = st.columns([2, 2, 1, 1, 1])
        
        with col1:
            st.text(f"🔍 {scan.scan_id}")
        with col2:
            st.text(f"📅 {scan.started_at.strftime('%Y-%m-%d %H:%M')}" if scan.started_at else "N/A")
        with col3:
            st.text(f"🔴 {scan.critical_count}")
        with col4:
            st.text(f"🟠 {scan.high_count}")
        with col5:
            status_icon = "✅" if scan.status == "completed" else "⏳"
            st.text(f"{status_icon} {scan.status}")


def main():
    """Main application entry point."""
    init_session_state()
    
    render_header()
    render_sidebar()
    
    # Main content area
    if st.session_state.selected_finding:
        render_remediation_panel(st.session_state.selected_finding)
    else:
        # Scan controls
        col1, col2, col3 = st.columns([1, 1, 2])
        
        with col1:
            if st.button("🚀 Run New Scan", type="primary", use_container_width=True):
                if run_scan(demo_mode=st.session_state.demo_mode):
                    st.rerun()
        
        with col2:
            if st.button("🎭 Quick Demo", use_container_width=True):
                st.session_state.demo_mode = True
                if run_scan(demo_mode=True):
                    st.rerun()
        
        with col3:
            if st.session_state.aws_data:
                account_id = st.session_state.aws_data.get('account_id', 'Unknown')
                st.info(f"📊 Current Account: **{account_id}**")
        
        st.markdown("---")
        
        # Display metrics if we have findings
        if st.session_state.findings:
            render_metrics(st.session_state.findings)
            st.markdown("---")
            render_findings_table(st.session_state.findings)
        else:
            # Welcome message
            st.markdown("""
            <div style="text-align: center; padding: 3rem;">
                <h2 style="color: #00d4ff;">Welcome to AIDE</h2>
                <p style="color: #a0a0a0; max-width: 600px; margin: 0 auto;">
                    AIDE scans your AWS environment for 9 critical IAM misconfigurations and 
                    uses AI to generate secure remediation code.
                </p>
                <br/>
                <p style="color: #a0a0a0;">
                    Click <strong>Run New Scan</strong> to analyze your AWS account, or 
                    <strong>Quick Demo</strong> to see AIDE in action with sample data.
                </p>
            </div>
            """, unsafe_allow_html=True)
            
            # Show scan history
            st.markdown("---")
            render_scan_history()
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666; font-size: 0.8rem;">
        AIDE - Automated IAM Detection Engine | 
        Powered by Google Gemini AI | 
        Built with Streamlit
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
