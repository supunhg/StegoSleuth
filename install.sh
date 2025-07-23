#!/bin/bash

# Install script for StegoSleuth (Linux/macOS)

echo "🕵️‍♂️ Installing StegoSleuth..."

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Python version: $python_version"

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Install binwalk
echo "Installing binwalk..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y binwalk
    elif command -v yum &> /dev/null; then
        sudo yum install -y binwalk
    elif command -v pacman &> /dev/null; then
        sudo pacman -S binwalk
    else
        echo "Please install binwalk manually for your distribution"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    if command -v brew &> /dev/null; then
        brew install binwalk
    else
        echo "Please install Homebrew first: https://brew.sh/"
    fi
fi

# Make the main script executable
chmod +x stegosleuth.py

echo "✅ Installation complete!"
echo ""
echo "Usage:"
echo "  python3 stegosleuth.py image.png"
echo "  python3 stegosleuth.py image.png --check lsb"
echo "  python3 stegosleuth.py image.png --verbose --output results.txt"
echo ""
echo "Run tests:"
echo "  python3 -m pytest tests/"
