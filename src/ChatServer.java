import java.io.*;
import java.net.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.security.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.*;
import java.util.concurrent.*;
import java.util.HashMap;

public class ChatServer {
    private static int PORT = 1695; // default server port
    private static HashMap<String, String> userDatabase = new HashMap<>();
    private static Set<PrintWriter> clientWriters = new CopyOnWriteArraySet<>();
    private static Map<PrintWriter, String> clientUsernames = new ConcurrentHashMap<>(); // storing client usernames
    private static BlockingQueue<String> messageQueue = new LinkedBlockingQueue<>(); // Queue for messages
    private static Map<Socket, PrintWriter> socketMap = new ConcurrentHashMap<>(); // Store the association between Socket and PrintWriter
    public static SecretKey serverSecretKey;
    public static String encodedServerKey;
    private static Map<String, String> userCredentials = new HashMap<>();
    private static final String CREDENTIALS_FILE = "user_credentials.txt"; // Storing credentials in a txt file

    static {
        ClientHandler.loadUserCredentials();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        if (args.length == 1) {
            try {
                PORT = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid PORT number. Using the default PORT: " + PORT);
            }
        } else {
            System.err.println("Usage: java ChatServer <PORT>");
            System.err.println("Using the default PORT: " + PORT);
        }

        System.out.println("Chat Server started on PORT: " + PORT);
        ExecutorService pool = Executors.newFixedThreadPool(10);

        // Generate a server secret key for encryption/decryption
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        serverSecretKey = keyGenerator.generateKey();
        encodedServerKey = Base64.getEncoder().encodeToString(serverSecretKey.getEncoded());
        System.out.println("############# DEBUG - SERVER GENERATED ENCODED KEY: "+encodedServerKey); // ########### DEBUG: SERVER ENCODED SECRET KEY

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            while (true) {
                new ClientHandler(serverSocket.accept()).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class ClientHandler extends Thread {
        private Socket socket;
        private  PrintWriter out;
        private  BufferedReader in;
        private String username;
        private String encodedClientKey;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        public void run() {

            try {
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                out = new PrintWriter(socket.getOutputStream(), true);

                out.flush();

                // 1. Server receives client encoded key and stores it ############################
                // Receive the encoded client secret key from the client
                encodedClientKey = in.readLine(); // STORING THE CLIENTS ENCODED SECRET KEY
                System.out.println("############# DEBUG - RECEIVED CLIENT ENCODED KEY: "+encodedClientKey);

                // 2. Server sends its encoded key to client ############################
                // Sending the encodedServerKey to the client
                out.println(encodedServerKey);
                System.out.println("############# DEBUG - SENT SERVER ENCODED KEY TO CLIENT: "+
                        encodedServerKey); // DEBUG

                // Save the client's preferred nickname
                String username = in.readLine();

                // Ensure the username is unique
                while (usernameExists(username)) {
                    out.println("\n# SERVER #: Nickname is already taken. Please choose another one: ");
                    username = in.readLine();
                }

                out.println("Welcome to ChatApp. Please log in or register.");

                boolean ranOnce = false; // flag to ensure authenticate client runs only once
                if (!authenticateClient(out,in) && ranOnce == false) {
                    ranOnce = true;
                    //return; // Disconnect the client if authentication fails
                }

                // Notifying the client that their username was accepted
                out.println("\n# SERVER #: Nickname accepted. Welcome to ChatApp " + username + "!" +
                        " Type 'exit' at anytime to quit the chat.");
                out.println("\n# SERVER #: Start typing your message below!\n");
                out.flush();

                clientWriters.add(out);
                clientUsernames.put(out, username);

                // Notify other clients that a new user has joined
                broadcast("# SERVER #: " + username + " has joined the chat.", out);

                String clientMessage;
                while ((clientMessage = in.readLine()) != null) {
                    System.out.println("### DEBUG - Client " + username + " ENCRYPTED msg: "+clientMessage); // ########### DEBUG: ENCRYPTED MSG
                    String clientDecryptedMessage = clientDecrypt(clientMessage, encodedClientKey); // decrypting client msg using their key
                    System.out.println("### DEBUG - Client " + username + " DECRYPTED msg: "+clientDecryptedMessage); // ########### DEBUG: DECRYPTED MSG
                    broadcastEncrypted(username + ": " + clientDecryptedMessage,
                            out, serverSecretKey);
                }

            } catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException |
                     BadPaddingException | IllegalBlockSizeException e) {

                //out.println("# SERVER #: Client " + clientUsernames.get(out) + " has left the chat.");
                //System.out.println("# SERVER #: Client " + clientUsernames.get(out) + " has left the chat.");
                System.out.println(e);

            } finally {
                try {
                    socket.close();
                    clientWriters.remove(out);
                    broadcast("# SERVER #: " + clientUsernames.get(out) + " has left the chat.", out);
                    clientUsernames.remove(out);
                    socketMap.remove(socket); // Remove the association from socketMap
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        private static void loadUserCredentials() {
            try {
                BufferedReader reader = new BufferedReader(new FileReader(CREDENTIALS_FILE));
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split(":");
                    if (parts.length == 2) {
                        userCredentials.put(parts[0], parts[1]);
                    }
                }
                reader.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        private static void saveUserCredentials() {
            try {
                BufferedWriter writer = new BufferedWriter(new FileWriter(CREDENTIALS_FILE));
                for (Map.Entry<String, String> entry : userCredentials.entrySet()) {
                    writer.write(entry.getKey() + ":" + entry.getValue());
                    writer.newLine();
                }
                writer.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        private boolean authenticateClient(PrintWriter out, BufferedReader in)
                throws IOException,
                NoSuchPaddingException,
                IllegalBlockSizeException,
                NoSuchAlgorithmException,
                BadPaddingException,
                InvalidKeyException
        {
            while (true) {
                out.println("Enter 'login' to log in or 'register' to register:");
                String choice = in.readLine();
                //System.out.println("DEBUG1234: "+choice);
                String decryptedChoice = clientDecrypt(choice, encodedClientKey);
                //System.out.println("##### DEBUG DECRYPTED CHOICE: "+decryptedChoice);

                if ("login".equalsIgnoreCase(decryptedChoice)) {

                    out.println("Enter your username: ");
                    String user = in.readLine();
                    String username = clientDecrypt(user, encodedClientKey); //decrypted username

                    out.println("Enter your password: ");
                    String passwd = in.readLine();
                    String password = clientDecrypt(passwd, encodedClientKey); // decrypted password
                    String hashedPassword = HashUtil.hashPassword(password);

                    if (userCredentials.containsKey(username) && userCredentials.get(username).equals(hashedPassword)) {
                        out.println("Login successful!");
                        break;

                    } else {
                        out.println("Invalid username or password.");
                    }

                } else if ("register".equalsIgnoreCase(decryptedChoice)) {

                    out.println("Enter your desired username: ");
                    String user = in.readLine();
                    String username = clientDecrypt(user, encodedClientKey); //decrypted username

                    out.println("Enter your password: ");
                    String passwd = in.readLine();
                    String password = clientDecrypt(passwd, encodedClientKey); // decrypted password
                    String hashedPassword = HashUtil.hashPassword(password);

                    userCredentials.put(username, hashedPassword);
                    saveUserCredentials();

                    out.println("Registration successful!");
                    break;

                } else if ("exit".equalsIgnoreCase(decryptedChoice)) {
                    out.println("Terminating client connection.");
                    socket.close();
                } else {
                    out.println("Invalid choice.");
                }
            }
            return true;
        }

    }

    private static String getCurrentTimestamp() {
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
        return "[" + sdf.format(new Date()) + "]";
    }

    // Helper method to broadcast a message to all clients
    private static void broadcast(String message, PrintWriter sender) {
        for (PrintWriter writer : clientWriters) {
            if (writer != sender) {
                //String timestampedMessage = getCurrentTimestamp() + " " + message;
                try {
                    writer.println(message);
                } catch (Exception e) {
                    e.printStackTrace(); // Handle exceptions (client not reachable, etc)
                }
            }
        }
    }

    // Use this method to broadcast encrypted messages using the Server's SecretKey
    private static void broadcastEncrypted(String msg, PrintWriter sender, SecretKey serverSecretKey)
            throws
            NoSuchPaddingException,
            IllegalBlockSizeException,
            NoSuchAlgorithmException,
            BadPaddingException,
            InvalidKeyException
    {
        //String serverEncryptedMsg = serverEncrypt(msg, serverSecretKey);
        String serverEncryptedMsg = serverEncrypt(getCurrentTimestamp() + " " + msg, serverSecretKey);
        System.out.println("### DEBUG - SERVER ENCRYPTED broadcast msg: "+serverEncryptedMsg); // ########### DEBUG: DECRYPTED MSG
        System.out.println("### DEBUG - SERVER DECRYPTED broadcast msg: "+serverDecrypt(serverEncryptedMsg, serverSecretKey));

        for (PrintWriter writer : clientWriters) {
            if (writer != sender) {
                try {
                    writer.println("ENCRYPTED:///" + serverEncryptedMsg);
                } catch (Exception e) {
                    e.printStackTrace(); // Handle exceptions (client not reachable, etc)
                }
            }
        }
    }

    // Encrypt server broadcast messages using serverSecretKey
    private static String serverEncrypt(String message, SecretKey serverSecretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, serverSecretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String serverDecrypt(String serverEncryptedMessage, SecretKey serverSecretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, serverSecretKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(serverEncryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }
    // Decrypt client messages using encodedClientKey
    private static String clientDecrypt(String encryptedMessage, String encodedClientKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        byte[] keyBytes = Base64.getDecoder().decode(encodedClientKey);
        SecretKey secretKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }


    // Helper method to check if a username already exists
    private static boolean usernameExists(String username) {
        for (String existingUsername : clientUsernames.values()) {
            if (existingUsername.equals(username)) {
                return true;
            }
        }
        return false;
    }

}