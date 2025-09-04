"""
Threat Detection System - Streamlit Visualization Dashboard
Real-time threat monitoring and analytics dashboard
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
import logging

# Import our modules
from detect import HybridThreatDetector
from config import *

# Configure Streamlit page
st.set_page_config(
    page_title="Threat Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .alert-high {
        background-color: #ff6b6b;
        color: white;
        padding: 0.5rem;
        border-radius: 0.25rem;
        margin: 0.25rem 0;
    }
    .alert-medium {
        background-color: #ffa500;
        color: white;
        padding: 0.5rem;
        border-radius: 0.25rem;
        margin: 0.25rem 0;
    }
    .alert-low {
        background-color: #4caf50;
        color: white;
        padding: 0.5rem;
        border-radius: 0.25rem;
        margin: 0.25rem 0;
    }
</style>
""", unsafe_allow_html=True)

class ThreatDashboard:
    """
    Streamlit dashboard for threat detection visualization
    """
    
    def __init__(self):
        self.detector = None
        self.setup_session_state()
    
    def setup_session_state(self):
        """Initialize session state variables"""
        if 'alerts' not in st.session_state:
            st.session_state.alerts = []
        if 'detection_history' not in st.session_state:
            st.session_state.detection_history = []
        if 'model_performance' not in st.session_state:
            st.session_state.model_performance = self.load_model_performance()
        if 'detector_initialized' not in st.session_state:
            st.session_state.detector_initialized = False
    
    def load_model_performance(self):
        """Load model performance data"""
        try:
            performance_file = MODELS_DIR / "model_performance_report.csv"
            if performance_file.exists():
                return pd.read_csv(performance_file)
            else:
                return pd.DataFrame()
        except Exception as e:
            st.error(f"Error loading model performance: {e}")
            return pd.DataFrame()
    
    def initialize_detector(self):
        """Initialize the threat detector"""
        if not st.session_state.detector_initialized:
            with st.spinner("Initializing threat detection system..."):
                try:
                    self.detector = HybridThreatDetector()
                    st.session_state.detector_initialized = True
                    st.success("Threat detection system initialized successfully!")
                except Exception as e:
                    st.error(f"Error initializing detector: {e}")
                    return False
        else:
            self.detector = HybridThreatDetector()
        return True
    
    def render_header(self):
        """Render dashboard header"""
        st.markdown('<h1 class="main-header">🛡️ Threat Detection System Dashboard</h1>', 
                   unsafe_allow_html=True)
        
        # Status indicators
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                label="System Status",
                value="🟢 Online" if st.session_state.detector_initialized else "🔴 Offline"
            )
        
        with col2:
            st.metric(
                label="Total Alerts",
                value=len(st.session_state.alerts)
            )
        
        with col3:
            recent_alerts = [a for a in st.session_state.alerts 
                           if datetime.fromisoformat(a['timestamp']) > datetime.now() - timedelta(hours=24)]
            st.metric(
                label="Alerts (24h)",
                value=len(recent_alerts)
            )
        
        with col4:
            high_severity_alerts = [a for a in st.session_state.alerts 
                                  if a.get('severity') in ['HIGH', 'CRITICAL']]
            st.metric(
                label="High Priority",
                value=len(high_severity_alerts)
            )
    
    def render_sidebar(self):
        """Render sidebar controls"""
        st.sidebar.title("🎛️ Control Panel")
        
        # Detection mode selection
        st.sidebar.subheader("Detection Mode")
        detection_mode = st.sidebar.selectbox(
            "Select Detection Type",
            ["Real-time Monitoring", "File Analysis", "Manual Input", "Batch Processing"]
        )
        
        return detection_mode
    
    def render_realtime_monitoring(self):
        """Render real-time monitoring interface"""
        st.subheader("🔍 Real-time Threat Monitoring")
        
        # Auto-refresh toggle
        auto_refresh = st.checkbox("Auto-refresh (5 seconds)", value=False)
        
        if auto_refresh:
            time.sleep(5)
            st.experimental_rerun()
        
        # Manual refresh button
        if st.button("🔄 Refresh Now"):
            st.experimental_rerun()
        
        # Recent alerts
        self.render_recent_alerts()
        
        # Threat timeline
        self.render_threat_timeline()
    
    def render_file_analysis(self):
        """Render file analysis interface"""
        st.subheader("📁 File Analysis")
        
        uploaded_file = st.file_uploader(
            "Upload file for threat analysis",
            type=['csv', 'txt', 'json'],
            help="Upload CSV, TXT, or JSON files for threat detection analysis"
        )
        
        if uploaded_file is not None:
            if st.button("🔍 Analyze File"):
                with st.spinner("Analyzing file..."):
                    try:
                        # Save uploaded file temporarily
                        temp_path = Path(f"/tmp/{uploaded_file.name}")
                        with open(temp_path, "wb") as f:
                            f.write(uploaded_file.getbuffer())
                        
                        # Process file
                        if self.detector:
                            results = self.detector.process_file(str(temp_path))
                            
                            # Add results to session state
                            for result in results:
                                if result['final_verdict']['is_threat']:
                                    if 'alerts' in result:
                                        st.session_state.alerts.extend(result['alerts'])
                                st.session_state.detection_history.append(result)
                            
                            # Display results summary
                            threats_found = sum(1 for r in results if r['final_verdict']['is_threat'])
                            st.success(f"Analysis complete! Found {threats_found} threats out of {len(results)} items analyzed.")
                            
                            # Show detailed results
                            self.render_analysis_results(results)
                        
                        # Clean up temp file
                        temp_path.unlink(missing_ok=True)
                        
                    except Exception as e:
                        st.error(f"Error analyzing file: {e}")
    
    def render_manual_input(self):
        """Render manual input interface"""
        st.subheader("✋ Manual Threat Detection")
        
        input_type = st.selectbox(
            "Input Type",
            ["Text Analysis", "Network Data", "Email Content", "Custom Features"]
        )
        
        if input_type == "Text Analysis":
            text_input = st.text_area(
                "Enter text to analyze",
                placeholder="Paste suspicious text, URLs, or content here...",
                height=150
            )
            
            if st.button("🔍 Analyze Text") and text_input.strip():
                self.analyze_manual_input({'text': text_input, 'source': 'manual_input'})
        
        elif input_type == "Network Data":
            col1, col2 = st.columns(2)
            with col1:
                ip_input = st.text_input("IP Address", placeholder="192.168.1.1")
            with col2:
                domain_input = st.text_input("Domain", placeholder="example.com")
            
            if st.button("🔍 Analyze Network Data") and (ip_input or domain_input):
                data = {'source': 'manual_input'}
                if ip_input:
                    data['ip'] = ip_input
                if domain_input:
                    data['domain'] = domain_input
                self.analyze_manual_input(data)
        
        elif input_type == "Email Content":
            subject = st.text_input("Email Subject", placeholder="Email subject line")
            body = st.text_area("Email Body", placeholder="Email content...", height=100)
            sender = st.text_input("Sender", placeholder="sender@example.com")
            
            if st.button("🔍 Analyze Email") and (subject or body):
                email_text = f"Subject: {subject}\nFrom: {sender}\nBody: {body}"
                self.analyze_manual_input({'text': email_text, 'source': 'manual_email'})
    
    def analyze_manual_input(self, data):
        """Analyze manual input data"""
        if not self.detector:
            st.error("Detector not initialized!")
            return
        
        with st.spinner("Analyzing input..."):
            try:
                result = self.detector.detect_threats(data)
                
                # Add to session state
                if result['final_verdict']['is_threat']:
                    if 'alerts' in result:
                        st.session_state.alerts.extend(result['alerts'])
                st.session_state.detection_history.append(result)
                
                # Display result
                verdict = result['final_verdict']
                if verdict['is_threat']:
                    st.error(f"🚨 THREAT DETECTED! Confidence: {verdict['confidence']:.2%}")
                    st.write("**Threat Types:**", ", ".join(verdict['threat_types']))
                    st.write("**Severity:**", verdict['severity'])
                else:
                    st.success("✅ No threats detected")
                
                # Show detailed analysis
                with st.expander("Detailed Analysis"):
                    st.json(result)
                    
            except Exception as e:
                st.error(f"Error during analysis: {e}")
    
    def render_recent_alerts(self):
        """Render recent alerts section"""
        st.subheader("🚨 Recent Alerts")
        
        if not st.session_state.alerts:
            st.info("No alerts to display")
            return
        
        # Sort alerts by timestamp (most recent first)
        sorted_alerts = sorted(
            st.session_state.alerts,
            key=lambda x: x['timestamp'],
            reverse=True
        )
        
        # Display top 10 recent alerts
        for alert in sorted_alerts[:10]:
            severity = alert.get('severity', 'LOW')
            css_class = f"alert-{severity.lower()}"
            
            timestamp = datetime.fromisoformat(alert['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
            threat_types = ", ".join(alert.get('threat_types', []))
            
            st.markdown(f"""
            <div class="{css_class}">
                <strong>{severity}</strong> - {timestamp}<br>
                <strong>Threats:</strong> {threat_types}<br>
                <strong>Source:</strong> {alert.get('source_ip', 'Unknown')}<br>
                <strong>Confidence:</strong> {alert.get('confidence', 0):.2%}
            </div>
            """, unsafe_allow_html=True)
    
    def render_threat_timeline(self):
        """Render threat detection timeline"""
        st.subheader("📈 Threat Detection Timeline")
        
        if not st.session_state.alerts:
            st.info("No data available for timeline")
            return
        
        # Prepare data for timeline
        df_alerts = pd.DataFrame(st.session_state.alerts)
        df_alerts['timestamp'] = pd.to_datetime(df_alerts['timestamp'])
        df_alerts['hour'] = df_alerts['timestamp'].dt.floor('H')
        
        # Group by hour and severity
        timeline_data = df_alerts.groupby(['hour', 'severity']).size().reset_index(name='count')
        
        # Create timeline chart
        fig = px.line(
            timeline_data,
            x='hour',
            y='count',
            color='severity',
            title="Threats Detected Over Time",
            color_discrete_map={
                'LOW': '#4CAF50',
                'MEDIUM': '#FFA500',
                'HIGH': '#FF6B6B',
                'CRITICAL': '#8B0000'
            }
        )
        
        fig.update_layout(
            xaxis_title="Time",
            yaxis_title="Number of Threats",
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def render_analytics(self):
        """Render analytics and statistics"""
        st.subheader("📊 Threat Analytics")
        
        if not st.session_state.alerts:
            st.info("No data available for analytics")
            return
        
        df_alerts = pd.DataFrame(st.session_state.alerts)
        
        # Create analytics visualizations
        col1, col2 = st.columns(2)
        
        with col1:
            # Severity distribution
            severity_counts = df_alerts['severity'].value_counts()
            fig_severity = px.pie(
                values=severity_counts.values,
                names=severity_counts.index,
                title="Alert Severity Distribution",
                color_discrete_map={
                    'LOW': '#4CAF50',
                    'MEDIUM': '#FFA500',
                    'HIGH': '#FF6B6B',
                    'CRITICAL': '#8B0000'
                }
            )
            st.plotly_chart(fig_severity, use_container_width=True)
        
        with col2:
            # Threat type distribution
            threat_types = []
            for alert in st.session_state.alerts:
                threat_types.extend(alert.get('threat_types', []))
            
            if threat_types:
                threat_df = pd.DataFrame({'threat_type': threat_types})
                threat_counts = threat_df['threat_type'].value_counts()
                
                fig_threats = px.bar(
                    x=threat_counts.index,
                    y=threat_counts.values,
                    title="Threat Type Distribution",
                    labels={'x': 'Threat Type', 'y': 'Count'}
                )
                fig_threats.update_layout(xaxis_tickangle=-45)
                st.plotly_chart(fig_threats, use_container_width=True)
    
    def render_model_performance(self):
        """Render model performance metrics"""
        st.subheader("🤖 Model Performance")
        
        if st.session_state.model_performance.empty:
            st.info("No model performance data available. Train models first.")
            return
        
        df_perf = st.session_state.model_performance
        
        # Performance comparison chart
        metrics = ['Accuracy', 'Precision', 'Recall', 'F1 Score']
        
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=metrics,
            specs=[[{"secondary_y": False}, {"secondary_y": False}],
                   [{"secondary_y": False}, {"secondary_y": False}]]
        )
        
        for i, metric in enumerate(metrics):
            row = (i // 2) + 1
            col = (i % 2) + 1
            
            if metric in df_perf.columns:
                binary_data = df_perf[df_perf['Classification Type'] == 'binary']
                multiclass_data = df_perf[df_perf['Classification Type'] == 'multiclass']
                
                fig.add_trace(
                    go.Bar(
                        name=f'Binary {metric}',
                        x=binary_data['Model'],
                        y=binary_data[metric],
                        showlegend=(i == 0)
                    ),
                    row=row, col=col
                )
                
                fig.add_trace(
                    go.Bar(
                        name=f'Multiclass {metric}',
                        x=multiclass_data['Model'],
                        y=multiclass_data[metric],
                        showlegend=(i == 0)
                    ),
                    row=row, col=col
                )
        
        fig.update_layout(height=600, title_text="Model Performance Comparison")
        st.plotly_chart(fig, use_container_width=True)
        
        # Performance table
        st.subheader("📋 Detailed Performance Metrics")
        st.dataframe(df_perf, use_container_width=True)
    
    def render_analysis_results(self, results):
        """Render detailed analysis results"""
        st.subheader("📋 Analysis Results")
        
        threats_detected = [r for r in results if r['final_verdict']['is_threat']]
        benign_items = [r for r in results if not r['final_verdict']['is_threat']]
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Threats Detected", len(threats_detected))
        with col2:
            st.metric("Benign Items", len(benign_items))
        
        # Show threat details
        if threats_detected:
            st.subheader("🚨 Detected Threats")
            for i, threat in enumerate(threats_detected[:10]):  # Show top 10
                with st.expander(f"Threat {i+1} - {threat['final_verdict']['severity']}"):
                    verdict = threat['final_verdict']
                    st.write(f"**Confidence:** {verdict['confidence']:.2%}")
                    st.write(f"**Threat Types:** {', '.join(verdict['threat_types'])}")
                    st.write(f"**Detection Methods:** {', '.join(threat.get('final_verdict', {}).get('detection_method', []))}")
                    
                    if 'alerts' in threat:
                        for alert in threat['alerts']:
                            st.write(f"**Alert:** {alert['message']}")
    
    def run(self):
        """Main dashboard run function"""
        # Initialize detector
        if not self.initialize_detector():
            st.stop()
        
        # Render header
        self.render_header()
        
        # Render sidebar
        detection_mode = self.render_sidebar()
        
        # Main content based on selected mode
        if detection_mode == "Real-time Monitoring":
            self.render_realtime_monitoring()
        elif detection_mode == "File Analysis":
            self.render_file_analysis()
        elif detection_mode == "Manual Input":
            self.render_manual_input()
        elif detection_mode == "Batch Processing":
            st.subheader("🔄 Batch Processing")
            st.info("Batch processing functionality - upload multiple files for analysis")
        
        # Analytics section
        st.markdown("---")
        self.render_analytics()
        
        # Model performance section
        st.markdown("---")
        self.render_model_performance()
        
        # Footer
        st.markdown("---")
        st.markdown(
            "<div style='text-align: center; color: #666;'>"
            "🛡️ Threat Detection System Dashboard | "
            f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            "</div>",
            unsafe_allow_html=True
        )

def main():
    """Main function to run the dashboard"""
    dashboard = ThreatDashboard()
    dashboard.run()

if __name__ == "__main__":
    main()
