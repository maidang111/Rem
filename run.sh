#!/bin/bash

# Remedy Setup and Run Script

set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "🚀 Setting up Remedy in $SCRIPT_DIR..."

# Check if .venv exists
if [ ! -d ".venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source .venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install -r requirements.txt

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "⚙️  Creating .env file from template..."
    cp .env.example .env
    echo "⚠️  Please edit .env with your actual credentials before running!"
    echo "   - Add your GitHub personal access token"
    echo "   - The Devin API key is already configured"
fi

# Start the server
echo "🎯 Starting webhook server on port 5000..."
echo "📡 Don't forget to run ngrok in another terminal: ngrok http 5000"
python app.py
