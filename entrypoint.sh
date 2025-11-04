#!/bin/bash
# Entrypoint script to start ZAP and the web application

echo "=========================================="
echo "🚀 OWASP ZAP & Web Scanner Initialization"
echo "=========================================="

# Start ZAP daemon in background
echo ""
echo "📡 Starting OWASP ZAP daemon..."
/app/src/start_zap.sh &
ZAP_PID=$!

# Wait for ZAP to be ready (check both port and API)
echo "⏳ Waiting for ZAP to initialize (typically 30-90 seconds)..."
MAX_WAIT=180
COUNTER=0
ZAP_READY=0

while [ $COUNTER -lt $MAX_WAIT ]; do
    # Check if port is open
    if curl -s http://localhost:8080 > /dev/null 2>&1; then
        # Port is open, now check if API responds
        if curl -s http://localhost:8080/JSON/core/view/version/ > /dev/null 2>&1; then
            ZAP_VERSION=$(curl -s http://localhost:8080/JSON/core/view/version/ | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
            echo ""
            echo "✅ ZAP is ready on port 8080!"
            echo "📌 ZAP Version: ${ZAP_VERSION:-unknown}"
            echo "📌 ZAP API: http://localhost:8080"
            ZAP_READY=1
            break
        fi
    fi
    
    sleep 3
    COUNTER=$((COUNTER + 3))
    
    if [ $((COUNTER % 15)) -eq 0 ]; then
        echo "   ⏱️  Still waiting for ZAP... ${COUNTER}s / ${MAX_WAIT}s elapsed"
        
        # Check if ZAP process is still running
        if ! ps -p $ZAP_PID > /dev/null 2>&1; then
            echo "   ⚠️  ZAP process died, checking logs..."
            break
        fi
    fi
done

echo ""
if [ $ZAP_READY -eq 0 ]; then
    echo "⚠️  ZAP failed to start within ${MAX_WAIT}s"
    echo "⚠️  The scanner will continue but ZAP scans will be skipped"
    echo "💡 Check logs: docker logs <container-name> | grep ZAP"
else
    echo "🎯 ZAP is fully operational and ready for scanning!"
fi

echo ""
echo "=========================================="
echo "🌐 Starting Flask Web Application"
echo "=========================================="
echo "📍 Web Interface will be available at http://localhost:5000"
echo ""

# Start the Flask application
exec python src/web_interface.py
