#!/usr/bin/env python3
"""
Network Traffic Anomaly Detection CLI Tool
Command-line interface for the network anomaly detection system
"""

import argparse
import sys
import os
import subprocess
import time
import signal
from datetime import datetime

# Add backend directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

def start_monitoring(interface='lo'):
    """Start network traffic monitoring"""
    print(f"Starting network traffic monitoring on interface: {interface}")
    print("Dashboard will be available at: http://localhost:5000")
    print("Press Ctrl+C to stop monitoring")
    
    # Change to backend directory and start the Flask app
    backend_dir = os.path.join(os.path.dirname(__file__), 'backend')
    os.chdir(backend_dir)
    
    try:
        # Start the Flask application
        subprocess.run([sys.executable, 'app.py'], check=True)
    except KeyboardInterrupt:
        print("\nStopping network monitoring...")
    except subprocess.CalledProcessError as e:
        print(f"Error starting monitoring: {e}")
        return False
    
    return True

def start_dashboard():
    """Start the web dashboard only"""
    print("Starting Network Anomaly Detection Dashboard...")
    print("Dashboard available at: http://localhost:5000")
    
    backend_dir = os.path.join(os.path.dirname(__file__), 'backend')
    os.chdir(backend_dir)
    
    try:
        subprocess.run([sys.executable, 'app.py'], check=True)
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    except subprocess.CalledProcessError as e:
        print(f"Error starting dashboard: {e}")
        return False
    
    return True

def generate_report(output_file='report.txt'):
    """Generate a report of detected anomalies"""
    print(f"Generating anomaly detection report: {output_file}")
    
    # This would typically read from a database or log file
    # For now, we'll create a sample report
    report_content = f"""
Network Traffic Anomaly Detection Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
========================================

Summary:
- Monitoring Period: Last 24 hours
- Total Packets Analyzed: N/A (requires active monitoring)
- Anomalies Detected: N/A (requires active monitoring)
- Threat Level: Low

Note: This is a sample report. For actual data, start monitoring first.

Recommendations:
1. Start network monitoring to collect real data
2. Monitor the dashboard for real-time alerts
3. Review security policies based on detected patterns

For detailed analysis, access the web dashboard at:
http://localhost:5000
"""
    
    try:
        with open(output_file, 'w') as f:
            f.write(report_content)
        print(f"Report generated successfully: {output_file}")
        return True
    except Exception as e:
        print(f"Error generating report: {e}")
        return False

def run_tests():
    """Run system tests"""
    print("Running Network Anomaly Detection System Tests...")
    
    test_file = os.path.join(os.path.dirname(__file__), 'test_backend.py')
    
    if not os.path.exists(test_file):
        print("Test file not found. Please ensure test_backend.py exists.")
        return False
    
    try:
        result = subprocess.run([sys.executable, test_file], 
                              capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("Warnings/Errors:")
            print(result.stderr)
        
        return result.returncode == 0
    except Exception as e:
        print(f"Error running tests: {e}")
        return False

def show_status():
    """Show system status"""
    print("Network Anomaly Detection System Status")
    print("=" * 40)
    
    # Check if Flask app is running
    try:
        import requests
        response = requests.get('http://localhost:5000/api/status', timeout=5)
        if response.status_code == 200:
            status_data = response.json()
            print("✓ Dashboard: Running")
            print(f"✓ Monitoring: {'Active' if status_data.get('is_monitoring') else 'Inactive'}")
            print(f"✓ Interface: {status_data.get('interface', 'N/A')}")
            print(f"✓ Total Packets: {status_data.get('total_packets', 0)}")
            print(f"✓ Total Alerts: {status_data.get('total_alerts', 0)}")
        else:
            print("✗ Dashboard: Not responding")
    except:
        print("✗ Dashboard: Not running")
    
    print(f"\nDashboard URL: http://localhost:5000")
    print(f"System Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description='Network Traffic Anomaly Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --start --interface eth0     Start monitoring on eth0
  %(prog)s --dashboard                  Start web dashboard only
  %(prog)s --generate-report report.pdf Generate anomaly report
  %(prog)s --status                     Show system status
  %(prog)s --test                       Run system tests
        """
    )
    
    parser.add_argument('--start', action='store_true',
                       help='Start network traffic capture and monitoring')
    parser.add_argument('--dashboard', action='store_true',
                       help='Start the web dashboard')
    parser.add_argument('--interface', default='lo',
                       help='Network interface to monitor (default: lo)')
    parser.add_argument('--generate-report', dest='report_file',
                       help='Generate anomaly detection report')
    parser.add_argument('--status', action='store_true',
                       help='Show system status')
    parser.add_argument('--test', action='store_true',
                       help='Run system tests')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0.0')
    
    args = parser.parse_args()
    
    # Show help if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    # Handle different commands
    if args.start:
        success = start_monitoring(args.interface)
        sys.exit(0 if success else 1)
    
    elif args.dashboard:
        success = start_dashboard()
        sys.exit(0 if success else 1)
    
    elif args.report_file:
        success = generate_report(args.report_file)
        sys.exit(0 if success else 1)
    
    elif args.status:
        show_status()
    
    elif args.test:
        success = run_tests()
        sys.exit(0 if success else 1)
    
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
# End of file

