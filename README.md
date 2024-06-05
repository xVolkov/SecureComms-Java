# SecurusChat - A Secure Multi-Threaded Fully Encrypted ChatApp

### Overview
This repository contains a secure, multi-threaded chat application that ensures all communications between clients are encrypted. User passwords are securely hashed before storage, ensuring the highest level of security and privacy.

### Features
* __Secure Communication:__ All messages between clients and server are encrypted using AES-128.
* __Multi-Threaded Server:__ Handles multiple clients concurrently.
* __Hashed Passwords:__ Uses SHA-256 for storing user passwords.
* __User Registration and Login:__ Allows new users to register and existing users to log in.
* __Broadcast Messaging:__ Sends messages from one client to all other connected clients.
* __Private Messaging:__ Allows clients to send private messages to specific users.
* __Client Management:__ Keeps track of connected clients and manages their sessions.
* __Connection Handling:__ Gracefully handles client connections and disconnections.
* __Console-Based User Interface:__ Provides an intuitive interface for interaction.

### Files
* __ChatClient.java:__ Handles the client-side operations of the chat application.
* __ChatServer.java:__ Manages server-side operations and handles multiple client connections.
* __HashUtil.java:__ Provides utilities for hashing passwords.
* __user_credentials.txt:__ Contains sample user credentials stored as hashed values.

### Setup and Installation
1. Clone the repository
```sh 
git clone https://github.com/yourusername/secure-chatapp.git
cd secure-chatapp
```

2. Compile the source code
```sh
javac ChatClient.java ChatServer.java HashUtil.java
```

3. Run the server
```sh
java ChatServer
```

4. Run the client
```sh
java ChatClient
```

### Usage
1. Start the server by running the ChatServer class.
2. Start multiple clients by running the ChatClient class for each client.
3. Follow the prompts in the client console to log in or register.
4. Enjoy secure, encrypted communication with other connected clients.

### Security
* __Encryption:__ All communications between clients and server are encrypted using AES-128 to prevent eavesdropping.
* __Password Hashing:__ User passwords are hashed using SHA-256 algorithm to protect against password breaches.

### Contributing
Contributions are welcome! Please submit a pull request or open an issue to discuss what you would like to change.

### License
This project is licensed under the GPLv3 Licence.
