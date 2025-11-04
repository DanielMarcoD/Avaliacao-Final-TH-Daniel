#!/bin/bash
# Entrypoint script to start ZAP and the web application

# Start ZAP daemon
/app/src/start_zap.sh &

# Give ZAP a moment to initialize
sleep 5

# Start the Flask application
exec python src/web_interface.py
