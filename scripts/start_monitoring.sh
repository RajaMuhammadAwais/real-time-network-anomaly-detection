#!/bin/bash

# Network Traffic Anomaly Detection Startup Script

echo "=========================================="
echo "Network Traffic Anomaly Detection System"
echo "=========================================="

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3.11 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies if requirements.txt exists
if [ -f "requirements.txt" ]; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
fi

# Check if we need sudo for packet capture
echo ""
echo "Note: Network packet capture may require sudo privileges."
echo "If you encounter permission errors, run this script with sudo."
echo ""

# Navigate to backend directory
cd backend

# Start the application
echo "Starting Network Anomaly Detection Dashboard..."
echo "Dashboard will be available at: http://localhost:5000"
echo ""
echo "Press Ctrl+C to stop the application"
echo ""

python app.py

