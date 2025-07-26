import streamlit as st
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import re
import json
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import io
import base64

# Set page config
st.set_page_config(
        page_title="MITRE ATT&CK Log IDENTIFIER",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.7rem;
        font-weight: bold;
        color: #1F3B4D;
        text-align: center;
        margin-bottom: 2rem;
    }
    .alert-high {
        background-color: #f8d7da;
        color: #721c24;
        border-left: 5px solid #dc3545;
        padding: 1.25rem;
        margin: 1rem 0;
        border-radius: 0.5rem;
    }
    .alert-medium {
        background-color: #fff3cd;
        color: #856404;
        border-left: 5px solid #ffc107;
        padding: 1.25rem;
        margin: 1rem 0;
        border-radius: 0.5rem;
    }
    .alert-low {
        background-color: #d1ecf1;
        color: #0c5460;
        border-left: 5px solid #17a2b8;
        padding: 1.25rem;
        margin: 1rem 0;
        border-radius: 0.5rem;
    }
</style>
""", unsafe_allow_html=True)

class StreamlitMITREClassifier:
    def __init__(self):
        # Initialize the classifier in session state
        if 'classifier' not in st.session_state:
            st.session_state.classifier = self._initialize_classifier()
        
        self.classifier = st.session_state.classifier
    
    def _initialize_classifier(self):
        """Initialize the MITRE classifier"""
        # MITRE ATT&CK techniques mapping
        mitre_techniques = {
            'T1003': {'name': 'OS Credential Dumping', 'tactic': 'Credential Access', 'severity': 'High'},
            'T1055': {'name': 'Process Injection', 'tactic': 'Defense Evasion', 'severity': 'High'},
            'T1059': {'name': 'Command and Scripting Interpreter', 'tactic': 'Execution', 'severity': 'Medium'},
            'T1078': {'name': 'Valid Accounts', 'tactic': 'Defense Evasion', 'severity': 'Medium'},
            'T1190': {'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access', 'severity': 'High'},
            'T1566': {'name': 'Phishing', 'tactic': 'Initial Access', 'severity': 'High'},
            'T1570': {'name': 'Lateral Tool Transfer', 'tactic': 'Lateral Movement', 'severity': 'Medium'},
            'T1105': {'name': 'Ingress Tool Transfer', 'tactic': 'Command and Control', 'severity': 'Medium'},
            'T1083': {'name': 'File and Directory Discovery', 'tactic': 'Discovery', 'severity': 'Low'},
            'T1082': {'name': 'System Information Discovery', 'tactic': 'Discovery', 'severity': 'Low'},
            'T1057': {'name': 'Process Discovery', 'tactic': 'Discovery', 'severity': 'Low'},
            'T1049': {'name': 'System Network Connections Discovery', 'tactic': 'Discovery', 'severity': 'Low'},
            'T1018': {'name': 'Remote System Discovery', 'tactic': 'Discovery', 'severity': 'Low'},
            'T1016': {'name': 'System Network Configuration Discovery', 'tactic': 'Discovery', 'severity': 'Low'},
            'T1033': {'name': 'System Owner/User Discovery', 'tactic': 'Discovery', 'severity': 'Low'},
            'T1087': {'name': 'Account Discovery', 'tactic': 'Discovery', 'severity': 'Low'},
            'T1046': {'name': 'Network Service Scanning', 'tactic': 'Discovery', 'severity': 'Medium'},
            'T1543': {'name': 'Create or Modify System Process', 'tactic': 'Persistence', 'severity': 'High'},
            'T1547': {'name': 'Boot or Logon Autostart Execution', 'tactic': 'Persistence', 'severity': 'High'},
            'T1098': {'name': 'Account Manipulation', 'tactic': 'Persistence', 'severity': 'High'},
            'T1136': {'name': 'Create Account', 'tactic': 'Persistence', 'severity': 'Medium'},
            'T1574': {'name': 'Hijack Execution Flow', 'tactic': 'Persistence', 'severity': 'High'},
            'T1112': {'name': 'Modify Registry', 'tactic': 'Defense Evasion', 'severity': 'Medium'},
            'T1070': {'name': 'Indicator Removal on Host', 'tactic': 'Defense Evasion', 'severity': 'High'},
            'T1036': {'name': 'Masquerading', 'tactic': 'Defense Evasion', 'severity': 'Medium'},
            'T1027': {'name': 'Obfuscated Files or Information', 'tactic': 'Defense Evasion', 'severity': 'Medium'},
            'T1562': {'name': 'Impair Defenses', 'tactic': 'Defense Evasion', 'severity': 'High'},
            'T1021': {'name': 'Remote Services', 'tactic': 'Lateral Movement', 'severity': 'Medium'},
            'T1560': {'name': 'Archive Collected Data', 'tactic': 'Collection', 'severity': 'Low'},
            'T1005': {'name': 'Data from Local System', 'tactic': 'Collection', 'severity': 'Medium'},
            'T1041': {'name': 'Exfiltration Over C2 Channel', 'tactic': 'Exfiltration', 'severity': 'High'},
            'T1567': {'name': 'Exfiltration Over Web Service', 'tactic': 'Exfiltration', 'severity': 'High'},
            'T1486': {'name': 'Data Encrypted for Impact', 'tactic': 'Impact', 'severity': 'High'},
            'T1490': {'name': 'Inhibit System Recovery', 'tactic': 'Impact', 'severity': 'High'},
            'T1489': {'name': 'Service Stop', 'tactic': 'Impact', 'severity': 'Medium'},
            'T1529': {'name': 'System Shutdown/Reboot', 'tactic': 'Impact', 'severity': 'Medium'}
        }
        
        # Keywords and patterns for each technique
        technique_patterns = {
            'T1003': ['lsass', 'sam', 'ntds.dit', 'credential dump', 'hashdump', 'mimikatz', 'sekurlsa'],
            'T1055': ['process injection', 'dll injection', 'reflective dll', 'process hollowing', 'thread hijacking'],
            'T1059': ['powershell', 'cmd.exe', 'bash', 'python', 'wscript', 'cscript', 'rundll32'],
            'T1078': ['valid account', 'legitimate credential', 'authorized user', 'account compromise'],
            'T1190': ['web exploit', 'sql injection', 'xss', 'rce', 'web vulnerability', 'public exploit'],
            'T1566': ['phishing', 'malicious attachment', 'suspicious email', 'social engineering'],
            'T1570': ['lateral movement', 'psexec', 'wmic', 'remote execution', 'tool transfer'],
            'T1105': ['file download', 'wget', 'curl', 'powershell download', 'certutil', 'bitsadmin'],
            'T1083': ['dir', 'ls', 'find', 'where', 'tree', 'directory listing', 'file enumeration'],
            'T1082': ['systeminfo', 'uname', 'whoami', 'hostname', 'system information'],
            'T1057': ['tasklist', 'ps', 'get-process', 'process list', 'running processes'],
            'T1049': ['netstat', 'ss', 'network connections', 'listening ports'],
            'T1018': ['ping', 'nslookup', 'arp', 'network discovery', 'host discovery'],
            'T1016': ['ipconfig', 'ifconfig', 'route', 'network configuration'],
            'T1033': ['whoami', 'id', 'net user', 'user enumeration'],
            'T1087': ['net user', 'net group', 'account enumeration', 'user discovery'],
            'T1046': ['nmap', 'port scan', 'service scan', 'network scanning'],
            'T1543': ['sc create', 'systemctl', 'service install', 'daemon creation'],
            'T1547': ['startup', 'autostart', 'boot persistence', 'logon script'],
            'T1098': ['account modification', 'user privilege', 'password change'],
            'T1136': ['useradd', 'net user /add', 'account creation'],
            'T1574': ['dll hijack', 'path hijack', 'execution flow'],
            'T1112': ['reg add', 'registry modification', 'regedit'],
            'T1070': ['del', 'rm', 'clear logs', 'event log clear', 'wevtutil'],
            'T1036': ['masquerade', 'fake name', 'legitimate process', 'spoofing'],
            'T1027': ['obfuscation', 'encoded', 'encrypted', 'packed'],
            'T1562': ['disable antivirus', 'stop security', 'impair defense'],
            'T1021': ['rdp', 'ssh', 'telnet', 'remote desktop', 'remote access'],
            'T1560': ['zip', 'rar', 'compress', 'archive', 'winrar'],
            'T1005': ['file access', 'data collection', 'local data'],
            'T1041': ['data exfiltration', 'c2 channel', 'command control'],
            'T1567': ['cloud storage', 'file sharing', 'web service'],
            'T1486': ['ransomware', 'encrypt', 'crypto', 'locked files'],
            'T1490': ['vssadmin', 'shadow copy', 'backup deletion', 'recovery disable'],
            'T1489': ['service stop', 'sc stop', 'systemctl stop'],
            'T1529': ['shutdown', 'reboot', 'restart', 'system halt']
        }
        
        return {
            'techniques': mitre_techniques,
            'patterns': technique_patterns,
            'vectorizer': TfidfVectorizer(max_features=5000, ngram_range=(1, 2)),
            'model': None,
            'is_trained': False
        }
    
    def preprocess_log(self, log_entry):
        """Preprocess log entry for analysis"""
        log_entry = log_entry.lower()
        log_entry = re.sub(r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}', '', log_entry)
        log_entry = re.sub(r'\[\w+\]', '', log_entry)
        log_entry = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'IP_ADDRESS', log_entry)
        log_entry = re.sub(r'[a-zA-Z]:\\[^\s]+\\([^\s\\]+)', r'\1', log_entry)
        log_entry = re.sub(r'https?://([^/\s]+)/[^\s]*', r'\1', log_entry)
        return log_entry
    
    def generate_training_data(self):
        """Generate synthetic training data"""
        sample_logs = {
            'T1003': [
                'lsass.exe process access detected',
                'mimikatz credential dumping attempt',
                'suspicious sam file access',
                'ntds.dit file accessed by unknown process',
                'credential dump operation detected'
            ],
            'T1055': [
                'process injection detected in explorer.exe',
                'dll injection into running process',
                'reflective dll loading detected',
                'process hollowing technique identified',
                'thread hijacking attempt'
            ],
            'T1059': [
                'powershell.exe executed with encoded command',
                'cmd.exe spawned by office application',
                'suspicious python script execution',
                'wscript.exe running malicious script',
                'rundll32.exe suspicious execution'
            ],
            'T1083': [
                'dir command executed in system directory',
                'extensive file system enumeration detected',
                'find command searching for sensitive files',
                'recursive directory listing performed',
                'file enumeration activity'
            ],
            'T1082': [
                'systeminfo command executed',
                'whoami command run by suspicious process',
                'hostname enumeration detected',
                'system information gathering attempt',
                'uname command executed'
            ],
            'T1190': [
                'web application exploit attempt detected',
                'sql injection in web request',
                'rce vulnerability exploited',
                'suspicious web traffic pattern',
                'public exploit used'
            ],
            'T1566': [
                'phishing email with malicious attachment',
                'suspicious email link clicked',
                'social engineering attempt detected',
                'malicious document opened',
                'phishing campaign detected'
            ],
            'T1486': [
                'ransomware encryption detected',
                'multiple files encrypted rapidly',
                'crypto-locker behavior identified',
                'file extension changed to encrypted',
                'ransomware activity detected'
            ],
            'T1112': [
                'registry modification detected',
                'reg add command executed',
                'suspicious registry key created',
                'system registry tampered',
                'registry persistence detected'
            ],
            'T1070': [
                'event log cleared',
                'wevtutil clear-log executed',
                'log files deleted',
                'evidence removal detected',
                'indicator removal activity'
            ]
        }
        
        training_data = []
        for technique, logs in sample_logs.items():
            for log in logs:
                training_data.append({
                    'log_entry': log,
                    'technique': technique,
                    'tactic': self.classifier['techniques'][technique]['tactic'],
                    'technique_name': self.classifier['techniques'][technique]['name'],
                    'severity': self.classifier['techniques'][technique]['severity']
                })
        
        return pd.DataFrame(training_data)
    
    def train_model(self):
        """Train the classification model"""
        if self.classifier['is_trained']:
            return self.classifier['model']
        
        with st.spinner('Training MITRE ATT&CK classifier...'):
            training_data = self.generate_training_data()
            
            # Preprocess logs
            training_data['processed_log'] = training_data['log_entry'].apply(self.preprocess_log)
            
            # Vectorize text
            X = self.classifier['vectorizer'].fit_transform(training_data['processed_log'])
            y = training_data['technique']
            
            # Train model
            self.classifier['model'] = RandomForestClassifier(n_estimators=100, random_state=42)
            self.classifier['model'].fit(X, y)
            
            self.classifier['is_trained'] = True
            st.session_state.classifier = self.classifier
            
        return self.classifier['model']
    
    def predict_technique(self, log_entry):
        """Predict MITRE technique for a log entry"""
        if not self.classifier['is_trained']:
            self.train_model()
        
        processed_log = self.preprocess_log(log_entry)
        X = self.classifier['vectorizer'].transform([processed_log])
        
        prediction = self.classifier['model'].predict(X)[0]
        probabilities = self.classifier['model'].predict_proba(X)[0]
        max_prob = max(probabilities)
        
        technique_info = self.classifier['techniques'][prediction]
        
        return {
            'technique': prediction,
            'technique_name': technique_info['name'],
            'tactic': technique_info['tactic'],
            'severity': technique_info['severity'],
            'confidence': max_prob,
            'reasoning': self._get_reasoning(log_entry, prediction)
        }
    
    def _get_reasoning(self, log_entry, predicted_technique):
        """Generate reasoning for the prediction"""
        processed_log = self.preprocess_log(log_entry)
        matched_patterns = []
        
        if predicted_technique in self.classifier['patterns']:
            for pattern in self.classifier['patterns'][predicted_technique]:
                if pattern in processed_log:
                    matched_patterns.append(pattern)
        
        if matched_patterns:
            return f"Detected patterns: {', '.join(matched_patterns)}"
        else:
            return "Classification based on ML model analysis"
    
    def analyze_log_content(self, log_content):
        """Analyze log content"""
        if not self.classifier['is_trained']:
            self.train_model()
        
        results = []
        lines = log_content.strip().split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if line:
                try:
                    result = self.predict_technique(line)
                    result['line_number'] = line_num
                    result['original_log'] = line
                    results.append(result)
                except Exception as e:
                    st.error(f"Error processing line {line_num}: {e}")
                    continue
        
        return results

def main():
    # Header
    st.markdown('<div class="main-header">🛡️ MITRE ATT&CK IDENTIFIER</div>', unsafe_allow_html=True)
    st.markdown("---")
    
    # Initialize classifier
    classifier = StreamlitMITREClassifier()
    
    # Sidebar
    with st.sidebar:
        st.header("🛠️ Configuration")
        
        # Analysis mode
        analysis_mode = st.selectbox(
            "Choose Analysis Mode:",
            ["Single Log Entry", "Upload Log File", "Paste Log Content", "Demo Mode"]
        )
        
        # Train model button
        if st.button("🎯 Train/Retrain Model"):
            classifier.train_model()
            st.success("Model trained successfully!")
        
        # Show model info
        if classifier.classifier['is_trained']:
            st.success("✅ Model is trained and ready")
        else:
            st.warning("⚠️ Model needs training")
        
        st.markdown("---")
        
        # MITRE ATT&CK Info
        st.subheader("📊 Supported Techniques")
        techniques_df = pd.DataFrame([
            {
                'ID': tid,
                'Name': info['name'][:30] + '...' if len(info['name']) > 30 else info['name'],
                'Tactic': info['tactic'],
                'Severity': info['severity']
            }
            for tid, info in classifier.classifier['techniques'].items()
        ])
        
        st.dataframe(techniques_df, use_container_width=True, height=300)
    
    # Main content area
    if analysis_mode == "Single Log Entry":
        st.header("🔍 Single Log Entry Analysis")
        
        # Input
        log_entry = st.text_area(
            "Enter a log entry to analyze:",
            height=100,
            placeholder="Example: powershell.exe -encoded YQBzAGQAZgBhAHMAZABm"
        )
        
        if st.button("🔍 Analyze Log Entry") and log_entry:
            if not classifier.classifier['is_trained']:
                classifier.train_model()
            
            with st.spinner('Analyzing log entry...'):
                result = classifier.predict_technique(log_entry)
                
                # Display results
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Technique ID", result['technique'])
                
                with col2:
                    st.metric("Confidence", f"{result['confidence']:.1%}")
                
                with col3:
                    st.metric("Tactic", result['tactic'])
                
                with col4:
                    severity_color = {
                        'High': '🔴',
                        'Medium': '🟡',
                        'Low': '🟢'
                    }
                    st.metric("Severity", f"{severity_color[result['severity']]} {result['severity']}")
                
                # Detailed results
                st.markdown("### 📋 Detailed Analysis")
                
                severity_class = f"alert-{result['severity'].lower()}"
                st.markdown(f"""
                <div class="{severity_class}">
                    <h4>🎯 {result['technique']} - {result['technique_name']}</h4>
                    <p><strong>Tactic:</strong> {result['tactic']}</p>
                    <p><strong>Confidence:</strong> {result['confidence']:.1%}</p>
                    <p><strong>Reasoning:</strong> {result['reasoning']}</p>
                </div>
                """, unsafe_allow_html=True)
    
    elif analysis_mode == "Upload Log File":
        st.header("📁 Upload Log File Analysis")
        
        uploaded_file = st.file_uploader(
            "Choose a log file",
            type=['txt', 'log', 'csv'],
            help="Upload a text file containing log entries (one per line)"
        )
        
        if uploaded_file is not None:
            # Read file content
            try:
                content = uploaded_file.read().decode('utf-8')
                st.success(f"File uploaded successfully! ({len(content.split())} lines)")
                
                # Show preview
                with st.expander("📋 File Preview"):
                    st.text(content[:1000] + "..." if len(content) > 1000 else content)
                
                if st.button("🔍 Analyze Log File"):
                    analyze_logs(classifier, content)
            except Exception as e:
                st.error(f"Error reading file: {e}")
    
    elif analysis_mode == "Paste Log Content":
        st.header("📝 Paste Log Content Analysis")
        
        log_content = st.text_area(
            "Paste your log content here:",
            height=300,
            placeholder="Paste multiple log entries, one per line..."
        )
        
        if st.button("🔍 Analyze Log Content") and log_content:
            analyze_logs(classifier, log_content)
    
    elif analysis_mode == "Demo Mode":
        st.header("🎭 Demo Mode")
        
        demo_logs = [
            "powershell.exe -encoded YQBzAGQAZgBhAHMAZABm executed",
            "lsass.exe process access detected from unknown process",
            "systeminfo command executed by suspicious process",
            "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Multiple files encrypted with .crypto extension detected",
            "mimikatz credential dumping attempt",
            "wevtutil clear-log Security executed",
            "psexec lateral movement detected",
            "nmap port scan detected",
            "ransomware encryption behavior identified"
        ]
        
        st.markdown("### 🧪 Sample Log Entries")
        for i, log in enumerate(demo_logs, 1):
            st.code(f"{i}. {log}")
        
        if st.button("🔍 Analyze Demo Logs"):
            demo_content = "\n".join(demo_logs)
            analyze_logs(classifier, demo_content)

def analyze_logs(classifier, log_content):
    """Analyze log content and display results"""
    with st.spinner('Analyzing log entries...'):
        results = classifier.analyze_log_content(log_content)
    
    if not results:
        st.warning("No log entries found to analyze.")
        return
    
    # Summary metrics
    st.markdown("### 📊 Analysis Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Entries", len(results))
    
    with col2:
        unique_techniques = len(set(r['technique'] for r in results))
        st.metric("Unique Techniques", unique_techniques)
    
    with col3:
        unique_tactics = len(set(r['tactic'] for r in results))
        st.metric("Tactics Involved", unique_tactics)
    
    with col4:
        high_severity = sum(1 for r in results if r['severity'] == 'High')
        st.metric("High Severity", high_severity)
    
    # Severity distribution
    severity_counts = {'High': 0, 'Medium': 0, 'Low': 0}
    for result in results:
        severity_counts[result['severity']] += 1
    
    # Visualizations
    st.markdown("### 📈 Analysis Visualizations")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Severity pie chart
        fig_severity = px.pie(
            values=list(severity_counts.values()),
            names=list(severity_counts.keys()),
            title="Severity Distribution",
            color_discrete_map={
                'High': '#dc3545',
                'Medium': '#ffc107',
                'Low': '#28a745'
            }
        )
        st.plotly_chart(fig_severity, use_container_width=True)
    
    with col2:
        # Technique frequency
        technique_counts = {}
        for result in results:
            technique = f"{result['technique']}"
            technique_counts[technique] = technique_counts.get(technique, 0) + 1
        
        fig_techniques = px.bar(
            x=list(technique_counts.keys()),
            y=list(technique_counts.values()),
            title="Technique Frequency",
            labels={'x': 'Technique', 'y': 'Count'}
        )
        fig_techniques.update_layout(xaxis_tickangle=-45)
        st.plotly_chart(fig_techniques, use_container_width=True)
    
    # Tactic distribution
    tactic_counts = {}
    for result in results:
        tactic = result['tactic']
        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
    
    fig_tactics = px.bar(
        x=list(tactic_counts.keys()),
        y=list(tactic_counts.values()),
        title="MITRE ATT&CK Tactics Distribution",
        labels={'x': 'Tactic', 'y': 'Count'}
    )
    fig_tactics.update_layout(xaxis_tickangle=-45)
    st.plotly_chart(fig_tactics, use_container_width=True)
    
    # Detailed results
    st.markdown("### 📋 Detailed Results")
    
    # Filter options
    col1, col2, col3 = st.columns(3)
    
    with col1:
        severity_filter = st.selectbox(
            "Filter by Severity:",
            ['All', 'High', 'Medium', 'Low']
        )
    
    with col2:
        tactic_filter = st.selectbox(
            "Filter by Tactic:",
            ['All'] + list(set(r['tactic'] for r in results))
        )
    
    with col3:
        confidence_threshold = st.slider(
            "Minimum Confidence:",
            0.0, 1.0, 0.0, 0.1
        )
    
    # Apply filters
    filtered_results = results
    if severity_filter != 'All':
        filtered_results = [r for r in filtered_results if r['severity'] == severity_filter]
    if tactic_filter != 'All':
        filtered_results = [r for r in filtered_results if r['tactic'] == tactic_filter]
    filtered_results = [r for r in filtered_results if r['confidence'] >= confidence_threshold]
    
    # Display results
    for result in filtered_results:
        severity_class = f"alert-{result['severity'].lower()}"
        
        st.markdown(f"""
        <div class="{severity_class}">
            <h4>Line {result['line_number']}: {result['technique']} - {result['technique_name']}</h4>
            <p><strong>Tactic:</strong> {result['tactic']}</p>
            <p><strong>Severity:</strong> {result['severity']}</p>
            <p><strong>Confidence:</strong> {result['confidence']:.1%}</p>
            <p><strong>Reasoning:</strong> {result['reasoning']}</p>
            <p><strong>Original Log:</strong> <code>{result['original_log']}</code></p>
        </div>
        """, unsafe_allow_html=True)
    
    # Export results
    export_df = pd.DataFrame(results)
    csv = export_df.to_csv(index=False).encode('utf-8')

    st.download_button(
        label="📥 Download CSV Report",
        data=csv,
        file_name="mitre_analysis_results.csv",
        mime="text/csv"
    )


if __name__ == "__main__":
    main()