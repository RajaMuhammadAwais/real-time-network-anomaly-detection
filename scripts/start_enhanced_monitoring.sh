#!/bin/bash

# Enhanced Network Traffic Anomaly Detection System Startup Script
# This script starts the enhanced monitoring system with all advanced features

echo "🚀 Starting Enhanced Network Traffic Anomaly Detection System..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run setup first:"
    echo "   python3.11 -m venv venv"
    echo "   source venv/bin/activate"
    echo "   pip install -r requirements.txt"
    exit 1
fi

# Activate virtual environment
echo "📦 Activating virtual environment..."
source venv/bin/activate

# Check if required packages are installed
echo "🔍 Checking dependencies..."
python -c "import tensorflow, flask, scapy" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "❌ Missing dependencies. Installing..."
    pip install -r requirements.txt
fi

# Create logs directory
mkdir -p logs

# Set environment variables for TensorFlow
export TF_ENABLE_ONEDNN_OPTS=0
export TF_CPP_MIN_LOG_LEVEL=2

# Check for network interface permissions
echo "🔧 Checking network permissions..."
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Running without root privileges. Some network features may be limited."
    echo "   For full functionality, run with sudo or set capabilities:"
    echo "   sudo setcap cap_net_raw+eip \$(which python3.11)"
fi

# Start the enhanced application
echo "🌟 Starting enhanced monitoring system..."
echo "📊 Dashboard: http://localhost:5000"
echo "🔍 Threat Hunting: http://localhost:5000/threat_hunting.html"
echo ""
echo "Press Ctrl+C to stop the system"
echo "========================================"

cd backend
python enhanced_app.py

