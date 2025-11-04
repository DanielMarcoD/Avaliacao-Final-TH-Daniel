#!/bin/bash
# Script to start OWASP ZAP in daemon mode

# Check if ZAP is installed
if [ ! -f "/usr/local/bin/zap.sh" ]; then
    echo "❌ OWASP ZAP not found at /usr/local/bin/zap.sh"
    echo "🔍 Searching for ZAP installation..."
    
    # Try to find ZAP in common locations
    if [ -f "/opt/zaproxy/zap.sh" ]; then
        echo "✅ Found ZAP at /opt/zaproxy/zap.sh"
        ZAP_PATH="/opt/zaproxy/zap.sh"
    elif [ -f "/opt/ZAP_2.15.0/zap.sh" ]; then
        echo "✅ Found ZAP at /opt/ZAP_2.15.0/zap.sh"
        ZAP_PATH="/opt/ZAP_2.15.0/zap.sh"
    else
        echo "❌ Could not find ZAP installation"
        exit 1
    fi
else
    ZAP_PATH="/usr/local/bin/zap.sh"
fi

echo "🔧 Starting OWASP ZAP daemon on port 8080..."
echo "   ZAP Path: $ZAP_PATH"
echo "   Host: 0.0.0.0 (all interfaces)"
echo "   API Key: disabled"
echo "   Config: optimized for container"

# Create ZAP home directory if it doesn't exist
mkdir -p ~/.ZAP

# Set DISPLAY for headless mode
export DISPLAY=:99

# Run ZAP with all necessary flags
exec "$ZAP_PATH" \
    -daemon \
    -host 0.0.0.0 \
    -port 8080 \
    -config api.disablekey=true \
    -config api.addrs.addr.name=.* \
    -config api.addrs.addr.regex=true \
    -config connection.timeoutInSecs=600 \
    -config spider.maxDuration=5 \
    -config scanner.maxScanDurationInMins=15 \
    -config ajaxSpider.maxDuration=5
