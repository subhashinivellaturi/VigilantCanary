#!/usr/bin/env python
import sys
import os
import socket
import subprocess

sys.path.insert(0, os.path.dirname(__file__))

from app.main import app
import uvicorn

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def kill_process_on_port(port):
    try:
        result = subprocess.run(f'netstat -ano | findstr :{port}', shell=True, capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        pids_to_kill = []
        for line in lines:
            if str(port) in line and 'LISTENING' in line:
                parts = line.split()
                if len(parts) >= 5:
                    pid = parts[-1]
                    if pid != '0' and pid.isdigit():
                        pids_to_kill.append(pid)
        
        for pid in pids_to_kill:
            try:
                subprocess.run(['taskkill', '/PID', pid, '/F'], check=True)
                print(f"Killed process {pid} using port {port}")
            except subprocess.CalledProcessError:
                print(f"Could not kill process {pid}")
    except Exception as e:
        print(f"Error killing process on port {port}: {e}")

if __name__ == "__main__":
    port = 8007
    if is_port_in_use(port):
        print(f"Port {port} is in use. Attempting to kill existing process...")
        kill_process_on_port(port)
    
    try:
        uvicorn.run(app, host="127.0.0.1", port=port)
    except Exception as e:
        print(f"Error running server: {e}")
        import traceback
        traceback.print_exc()