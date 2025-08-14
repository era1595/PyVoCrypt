import pyaudio
import socket
import threading
import sys
import ssl
import base64
import os
import time
import zlib  # Added for compression
import numpy as np  # Added for audio processing
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
from pynput import keyboard

# --- SETTINGS ---
FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 44100
CHUNK = 512  # Chunk size can be optimized for lower latency

# --- Server Information ---
TCP_SERVER_HOST = 'SERVER_IP_ADRESS_OR_DOMAIN'
UDP_SERVER_HOST = 'SERVER_IP_ADRESS_OR_DOMAIN'
TCP_PORT = 12345
UDP_PORT = 12346

# --- Global Variables ---
AESGCM_ENCRYPT = None
AESGCM_DECRYPT = None
shutdown_event = threading.Event()

# --- Global variables for audio sending status ---
can_talk = threading.Event()
talk_mode = "open_mic"
listener_thread = None
volume_gain = None # Global variable for volume level

# --- Function to find resource path for PyInstaller ---
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# --- SECURE AUTHENTICATION ---
def authenticate(root):
    global AESGCM_ENCRYPT, AESGCM_DECRYPT
    udp_client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    username = simpledialog.askstring("Login", "Username:", parent=root)
    if not username: return None, None
        
    password = simpledialog.askstring("Login", "Password:", show='*', parent=root)
    if not password: return None, None

    try:
        crt_path = resource_path('server.crt')
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=crt_path)
    except FileNotFoundError:
        messagebox.showerror("Error", f"'server.crt' file not found. Expected path: {crt_path}")
        return None, None

    try:
        with socket.create_connection((TCP_SERVER_HOST, TCP_PORT)) as tcp_socket:
            with ssl_context.wrap_socket(tcp_socket, server_hostname=TCP_SERVER_HOST) as secure_socket:
                auth_str = f"{username}:{password}"
                secure_socket.sendall(auth_str.encode('utf-8'))
                response = secure_socket.recv(1024).decode('utf-8')
                
                if response.startswith("ACCEPT:"):
                    _, b64_key, auth_token = response.split(':', 2)
                    aes_key = base64.b64decode(b64_key)
                    AESGCM_ENCRYPT = AESGCM(aes_key)
                    AESGCM_DECRYPT = AESGCM(aes_key)
                    print("Login successful! ✅")
                    return udp_client_socket, auth_token
                else:
                    messagebox.showerror("Login Failed", f"Server denied access.\nReason: {response}")
                    return None, None
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during authentication: {e}")
        return None, None

# --- Keyboard listener functions ---
def on_press(key):
    global talk_mode
    if talk_mode == "ptt" and key == keyboard.Key.alt_l:
        if not can_talk.is_set():
            can_talk.set()

def on_release(key):
    global talk_mode
    if talk_mode == "ptt" and key == keyboard.Key.alt_l:
        if can_talk.is_set():
            can_talk.clear()

def start_keyboard_listener():
    global listener_thread
    listener = keyboard.Listener(on_press=on_press, on_release=on_release)
    listener.start()
    listener_thread = listener
    print("Keyboard listener started.")

# --- UPDATED: Audio Processing ---
def send_audio(udp_socket, stream):
    """Reads audio from the microphone, adjusts volume, compresses, encrypts, and sends it."""
    print("Listening to microphone...")
    while not shutdown_event.is_set():
        if not can_talk.is_set() or not volume_gain:
            time.sleep(0.02)
            continue
        try:
            # 1. Read raw audio data
            data = stream.read(CHUNK, exception_on_overflow=False)

            # 2. Adjust volume (with numpy)
            gain = volume_gain.get()
            if gain != 1.0: # Process only if necessary
                audio_samples = np.frombuffer(data, dtype=np.int16)
                # Amplify/reduce audio and prevent clipping
                adjusted_samples = np.clip(audio_samples * gain, -32768, 32767).astype(np.int16)
                processed_data = adjusted_samples.tobytes()
            else:
                processed_data = data

            # 3. Compress the data
            compressed_data = zlib.compress(processed_data)

            # 4. Encrypt and send the data
            nonce = os.urandom(12)
            encrypted_data = AESGCM_ENCRYPT.encrypt(nonce, compressed_data, None)
            udp_socket.sendto(nonce + encrypted_data, (UDP_SERVER_HOST, UDP_PORT))
        except (AttributeError, TypeError, OSError):
            break
        except Exception as e:
            print(f"[ERROR] Audio sending stopped: {e}")
            break
    print("Audio sending thread stopped.")

def receive_audio(udp_socket, stream):
    """Receives encrypted data, decrypts it, decompresses it, and plays it."""
    print("Speaker ready...")
    while not shutdown_event.is_set():
        try:
            # 1. Receive the encrypted packet
            encrypted_packet, _ = udp_socket.recvfrom(2048)
            if shutdown_event.is_set(): break
            
            # 2. Decrypt the data
            nonce = encrypted_packet[:12]
            ciphertext = encrypted_packet[12:]
            compressed_data = AESGCM_DECRYPT.decrypt(nonce, ciphertext, None)
            
            # 3. NEW: Decompress the data
            decrypted_data = zlib.decompress(compressed_data)
            
            # 4. Play the audio
            stream.write(decrypted_data)
        except (AttributeError, TypeError, OSError, ConnectionAbortedError, ConnectionResetError):
            break
        except Exception as e:
            # Skip corrupted packets
            print(f"Audio receiving error (skipped): {e}")
            continue
    print("Audio receiving thread stopped.")


# --- MAIN PROGRAM FLOW ---
if __name__ == "__main__":
    p = None
    input_stream = None
    output_stream = None
    udp_socket = None

    try:
        initial_root = tk.Tk()
        initial_root.withdraw()

        if 'SERVER' in TCP_SERVER_HOST:
            messagebox.showwarning("Warning", "Please update the server information!")
            sys.exit(1)

        udp_socket, token = authenticate(initial_root)
        initial_root.destroy()

        if udp_socket and token:
            p = pyaudio.PyAudio()
            input_stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK)
            output_stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, output=True, frames_per_buffer=CHUNK)

            try:
                udp_socket.sendto(token.encode('utf-8'), (UDP_SERVER_HOST, UDP_PORT))
                print("Voice chat starting...")
            except Exception as e:
                messagebox.showerror("Error", f"UDP token sending error: {e}")
                raise
            
            can_talk.set()

            sender_thread = threading.Thread(target=send_audio, args=(udp_socket, input_stream))
            receiver_thread = threading.Thread(target=receive_audio, args=(udp_socket, output_stream))
            sender_thread.start()
            receiver_thread.start()
            
            start_keyboard_listener()

            # --- CONTROL WINDOW ---
            control_window = tk.Tk()
            control_window.title("Connection Active")
            control_window.geometry("300x280") # Window size updated
            control_window.resizable(False, False)
            
            # Volume gain variable is created here
            volume_gain = tk.DoubleVar(value=1.0)

            def on_closing():
                if messagebox.askokcancel("Exit", "Are you sure you want to end the connection?"):
                    shutdown_event.set()
                    if listener_thread:
                        listener_thread.stop()
                    control_window.destroy()
            
            control_window.protocol("WM_DELETE_WINDOW", on_closing)

            main_frame = tk.Frame(control_window, padx=10, pady=10)
            main_frame.pack(expand=True, fill='both')

            label = tk.Label(main_frame, text="Connected to voice chat.", pady=5)
            label.pack()

            close_button = tk.Button(main_frame, text="Disconnect", command=on_closing, bg="#e74c3c", fg="white", relief='flat', font=('Helvetica', 10, 'bold'))
            close_button.pack(pady=5, fill='x')
            
            mode_var = tk.BooleanVar()
            
            def toggle_mode():
                global talk_mode
                if mode_var.get():
                    talk_mode = "ptt"
                    can_talk.clear()
                    mute_button.pack_forget()
                    status_label.config(text="Mode: Push-to-Talk (Hold Left ALT)")
                else:
                    talk_mode = "open_mic"
                    can_talk.set()
                    mute_button.config(text="Mute Microphone")
                    mute_button.pack(pady=5, fill='x')
                    status_label.config(text="Mode: Open Mic")

            style = ttk.Style(control_window)
            style.configure('TCheckbutton', indicatorrelief='flat', background=main_frame.cget('bg'))
            
            switch_frame = tk.Frame(main_frame)
            tk.Label(switch_frame, text="Open Mic").pack(side='left')
            mode_switch = ttk.Checkbutton(switch_frame, variable=mode_var, onvalue=True, offvalue=False, style='TCheckbutton', command=toggle_mode)
            mode_switch.pack(side='left', padx=5)
            tk.Label(switch_frame, text="Push-to-Talk").pack(side='left')
            switch_frame.pack(pady=10)

            def toggle_mute():
                if talk_mode == "open_mic":
                    if can_talk.is_set():
                        can_talk.clear()
                        mute_button.config(text="Unmute Microphone")
                    else:
                        can_talk.set()
                        mute_button.config(text="Mute Microphone")

            mute_button = tk.Button(main_frame, text="Mute Microphone", command=toggle_mute, bg="#3498db", fg="white", relief='flat', font=('Helvetica', 10))
            mute_button.pack(pady=5, fill='x')

            # --- VOLUME ADJUSTER ---
            volume_frame = tk.Frame(main_frame)
            volume_frame.pack(pady=10, fill='x')
            
            volume_label = tk.Label(volume_frame, text="Volume:")
            volume_label.pack(side='left', padx=(0, 5))
            
            volume_slider = ttk.Scale(
                volume_frame, 
                from_=0.1, 
                to=10.0,  # Maximum amplification ratio increased again
                orient='horizontal', 
                variable=volume_gain,
                command=lambda s: volume_gain.set(float(s)) # Update the value instantly
            )
            volume_slider.pack(expand=True, fill='x')
            # --- End ---

            status_label = tk.Label(main_frame, text="Mode: Open Mic", font=('Helvetica', 9), fg='grey')
            status_label.pack(pady=5, side='bottom')
            
            control_window.mainloop()

            sender_thread.join(timeout=2)
            receiver_thread.join(timeout=2)

    except Exception as main_exc:
        print(f"An error occurred in the main program: {main_exc}")
    finally:
        print("[SHUTDOWN] Cleaning up all resources...")
        shutdown_event.set()
        if listener_thread:
            listener_thread.stop()
            print("Keyboard listener stopped.")
        if udp_socket:
            udp_socket.close()
            print("UDP socket closed.")
        if input_stream:
            input_stream.stop_stream()
            input_stream.close()
            print("Input stream closed.")
        if output_stream:
            output_stream.stop_stream()
            output_stream.close()
            print("Output stream closed.")
        if p:
            p.terminate()
            print("PyAudio terminated.")
        print("[SHUTDOWN] Cleanup complete.")
        sys.exit(0)
