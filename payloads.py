import subprocess

try:
    result = subprocess.run(['whoami'], capture_output=True, text=True, check=True)
    print(result.stdout)
except subprocess.CalledProcessError as e:
    print(f"Error: {e}")
    print(e.stderr)