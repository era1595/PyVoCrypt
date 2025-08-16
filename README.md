PyVoCrypt

(If anyone wants to contribute, I am completely open to suggestions and pull requests, and I would even be happy if you contribute.) 

PyVoCrypt is a low-latency, end-to-end encrypted (AES-GCM) voice chat application written in Python. It operates on a client-server architecture with a strong focus on secure communication.



Features

Strong Encryption: All voice data is encrypted using AES-256-GCM with ephemeral keys generated for each session.



Secure Authentication: User credentials are sent over TLS and verified on the server using Argon2 hashes.



Audio Optimization: Voice data is made more efficient by being compressed with zlib and having its volume adjusted with numpy.



Speaking Modes: Ability to switch between "Open Microphone" and "Push-to-Talk" (Left ALT) modes.



User-Friendly Interface: A simple control panel built with Tkinter.



Installation

Prerequisites:



Python 3.8+

pip package manager



Steps

Clone the Repository:



git clone https://github.com/era1595/PyVoCrypt.git

cd PyVoCrypt



Install Dependencies:

The project uses several external libraries. You can easily install them using the requirements.txt file:



pip install -r requirements.txt



Usage

1\. Server-Side

Before running the server, you need to generate your own SSL certificate.



Example command for Linux/macOS:



openssl req -new -x509 -days 365 -nodes -out server.crt -keyout server.key



Move the generated server.crt and server.key files into the server/ directory.



Use the passwordhasher.py script to hash usernames and passwords with Argon2, then add them to the relevant section of the server code, following the example provided in the code.



Run the server file server/PyVoCryptS.py:



python server/PyVoCryptS.py



2\. Client-Side

Copy the server.crt file you generated on the server into the client/ directory.



Open the client/PyVoCryptC.py file with a text editor and enter your server's IP address or domain:



TCP\_SERVER\_HOST = 'SERVER\_IP\_OR\_DOMAIN'

UDP\_SERVER\_HOST = 'SERVER\_IP\_OR\_DOMAIN'



Run the client:



python client/PyVoCryptC.py



In the window that opens, log in with the username and password you defined on the server.



Technical Notes:



The code currently uses a shared AES-GCM key for the session. While this method is already strong, it could be upgraded to a more advanced key exchange mechanism (like Diffie-Hellman) for enhanced security (Perfect Forward Secrecy).



The reason for having separate address variables for TCP and UDP ports is to facilitate the use of tunneling services. Since users whose servers are behind a tunnel might have different public-facing domains for different ports, this approach was chosen. (Ports also may be different don't forget to change them.)



The project's main limitation is the lack of acoustic echo cancellation (AEC). While it would be easy to add a third-party AEC service via an API, it would come at a cost. I have been attempting to integrate AEC using the native audio management APIs of Windows and macOS. However, these interfaces operate at a much lower level than Python (e.g., Windows COM), making them error-prone and often incompatible with certain hardware or software configurations (it doesn't work on Windows 10 and only on specific builds of Windows 11). As far as I know, this process is much simpler on GNU/Linux and doesn't require extra code changes or plugins; you just need to enable AEC for your main microphone and speaker with a specific command (or set a virtual microphone with AEC enabled as your primary device). On Windows, if you have a sound enhancement suite (like Realtek Audio Console, etc.), you may be able to enable system-wide AEC through it.

The system currently does not have an internal heartbeat system and the server does not track when a client leaves. 


License

This project is licensed under the MIT License.

