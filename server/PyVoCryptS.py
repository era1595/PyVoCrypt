import socket
import threading
import ssl
import secrets
import base64
import sys
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# --- SETTINGS ---
TCP_HOST = '0.0.0.0'
TCP_PORT = 12345
UDP_HOST = '0.0.0.0'
UDP_PORT = 12346

# --- Shared Encryption Key ---
SHARED_AES_KEY = secrets.token_bytes(16)
print("[SETUP] Shared AES key generated for the session.")

# --- SECURE USER DATABASE ---
USER_DATABASE = {
    'user1': '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$iVbaziJj/KmsA82GPGkBEunv3oD1xVSSg3sA9jIf1fE', # Password: 'sifre123'
    'user2': '$argon2id$v=19$m=65536,t=3,p=4$YW5vdGhlcnNhbHQ$H133GTVo4w3YjA7M2YGjol9nL2MjdwbHkZ2o94F/acU'  # Password: 'guvenlisifre'
}

# --- Shared Data Structures ---
lock = threading.Lock()
authenticated_clients = {}
pending_verification = {}
ph = PasswordHasher()

# --- UDP AUDIO FORWARDER ---
def udp_audio_forwarder():
    """Processes incoming UDP packets and forwards them to other clients except the sender."""
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((UDP_HOST, UDP_PORT))
    print(f"[UDP] Encrypted audio server listening on {UDP_HOST}:{UDP_PORT}...")

    while True:
        try:
            data, addr = udp_socket.recvfrom(4096)

            # Check if the incoming packet is a verification token
            try:
                token = data.decode('utf-8')
                with lock:
                    if token in pending_verification:
                        username = pending_verification.pop(token)
                        authenticated_clients[addr] = username
                        print(f"✅ [UDP VERIFY] UDP address for user {username} verified as {addr}.")
                        print(f"Active users: {len(authenticated_clients)}")
                        continue # Don't forward the verification packet to others
            except (UnicodeDecodeError, KeyError):
                # This is an audio packet, not for verification.
                pass

            # --- Forwarding Logic ---
            # Forward the packet to all other authenticated clients except the sender.
            with lock:
                if addr in authenticated_clients:
                    # We iterate over a copy of the dictionary's keys using list().
                    # This prevents errors if the dictionary changes during iteration.
                    for client_addr in list(authenticated_clients.keys()):
                        # If the address in the loop is NOT the sender's address...
                        if client_addr != addr:
                            # ...send the packet to that address.
                            udp_socket.sendto(data, client_addr)

        except Exception as e:
            print(f"[UDP ERROR] Unexpected error during audio forwarding: {e}")
            # Instead of breaking the loop on an error, we can continue

# --- SECURE CLIENT AUTHENTICATION (TCP/TLS) ---
def handle_client_auth(secure_conn, addr):
    """Handles the incoming TCP/TLS connection from the client and performs authentication."""
    print(f"[TCP/TLS] New secure connection request from {addr}.")
    try:
        data = secure_conn.recv(1024).decode('utf-8')
        username, password = data.strip().split(':', 1)

        stored_hash = USER_DATABASE.get(username)

        if not stored_hash:
            print(f"[AUTH] User '{username}' not found.")
            secure_conn.sendall(b'DENY:INVALID_CREDENTIALS')
            return

        try:
            ph.verify(stored_hash, password)
            print(f"[AUTH] User '{username}' verified credentials.")
            
            # Create a unique UDP verification token
            auth_token = secrets.token_hex(16)
            with lock:
                pending_verification[auth_token] = username

            # Send the Base64 encoded AES key and token to the client
            b64_key = base64.b64encode(SHARED_AES_KEY).decode('utf-8')
            response = f"ACCEPT:{b64_key}:{auth_token}"
            secure_conn.sendall(response.encode('utf-8'))
            
            print(f"✅ [AUTH] '{username}' APPROVED. Token sent for UDP verification.")

        except VerifyMismatchError:
            print(f"[AUTH] Invalid password for '{username}'.")
            secure_conn.sendall(b'DENY:INVALID_CREDENTIALS')

    except (ValueError, IndexError):
        print(f"[TCP/TLS] Invalid data format received from {addr}.")
    except Exception as e:
        print(f"[TCP/TLS] An error occurred during authentication: {e}")
    finally:
        secure_conn.close()

# --- MAIN SERVER ---
def start_server():
    """Starts the server, sets up UDP and TCP listeners."""
    # We start the UDP thread as a daemon so it closes when the main program exits.
    udp_thread = threading.Thread(target=udp_audio_forwarder, daemon=True)
    udp_thread.start()

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        # Load certificate and key files
        ssl_context.load_cert_chain(certfile='server.crt', keyfile='server.key')
    except FileNotFoundError:
        print("\n[ERROR] 'server.crt' or 'server.key' not found. Please generate the certificates.")
        print("Example command: openssl req -new -x509 -days 365 -nodes -out server.crt -keyout server.key")
        return
    except ssl.SSLError as e:
        print(f"\n[ERROR] An SSL error occurred while loading the certificate: {e}")
        print("Please ensure your certificate and key files are valid.")
        return

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind((TCP_HOST, TCP_PORT))
    tcp_socket.listen(5)
    print(f"[TCP/TLS] Secure authentication server listening on {TCP_HOST}:{TCP_PORT}...")
    print("Press Ctrl+C in this terminal to shut down the server.")

    try:
        while True:
            conn, addr = tcp_socket.accept()
            try:
                secure_conn = ssl_context.wrap_socket(conn, server_side=True)
                auth_thread = threading.Thread(target=handle_client_auth, args=(secure_conn, addr), daemon=True)
                auth_thread.start()
            except ssl.SSLError as e:
                print(f"[WARNING] Invalid SSL connection from {addr} rejected: {e}")
                conn.close()
            except Exception as e:
                print(f"[ERROR] Error while accepting connection: {e}")
                conn.close()

    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Ctrl+C detected, shutting down server...")
    finally:
        print("[SHUTDOWN] Closing main socket.")
        tcp_socket.close()

if __name__ == "__main__":
    # Let's add a check for the key file
    try:
        with open("server.key") as f:
            pass
    except FileNotFoundError:
        print("\n[STARTUP ERROR] 'server.key' file not found.")
        print("Please generate the certificate and key files before running the server.")
        sys.exit(1)
        
    start_server()
    print("[SHUTDOWN] Server program terminated successfully.")
    sys.exit(0)
