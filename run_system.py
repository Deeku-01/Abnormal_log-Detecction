import subprocess
import time
import sys
import os
import threading
import signal

def print_output(process, prefix):
    """Print output from a process with a prefix"""
    for line in iter(process.stdout.readline, ''):
        print(f"{prefix}: {line.strip()}")

def run_components():
    processes = []
    threads = []
    
    try:
        # Create/reset the log file
        with open('website_logs.json', 'w') as f:
            f.write('{"logs": []}')

        # Start Flask website
        website_process = subprocess.Popen(
            [sys.executable, 'website.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, 'FLASK_ENV': 'production'}
        )
        processes.append(('Website', website_process))
        print("Started website server...")
        time.sleep(2)  # Give website time to start

        # Start log detection
        detector_process = subprocess.Popen(
            [sys.executable, 'logDetection.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        processes.append(('Detector', detector_process))
        print("Started log detection system...")
        time.sleep(1)

        # Start test traffic generator
        test_process = subprocess.Popen(
            [sys.executable, 'test_website.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        processes.append(('Test', test_process))
        print("Started test traffic generator...")

        # Create and start output monitoring threads
        for prefix, process in processes:
            thread = threading.Thread(
                target=print_output,
                args=(process, prefix),
                daemon=True
            )
            thread.start()
            threads.append(thread)

        # Monitor processes
        while True:
            for prefix, process in processes:
                if process.poll() is not None:
                    error_msg = process.stderr.read()
                    if error_msg:
                        print(f"\n{prefix} error: {error_msg}")
                    return
            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\nShutting down all components...")
    finally:
        # Clean up processes
        for _, process in processes:
            try:
                process.terminate()
                process.wait(timeout=2)
            except:
                try:
                    process.kill()
                except:
                    pass
        print("All components stopped.")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda x, y: sys.exit(0))
    run_components() 