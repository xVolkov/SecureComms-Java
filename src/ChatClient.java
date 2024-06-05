import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class ChatClient {
    private static final String SERVER_ADDRESS = "localhost";
    private static int SERVER_PORT = 1695; // default server port
    public static SecretKey clientSecretKey;
    public static String encodedClientKey; // encoded as string so we can send it to server

    // Function to communicate with the server
    private static void communicateWithServer(PrintWriter out, BufferedReader in, BufferedReader userInput) throws IOException {

        //System.out.println("######### DEBUG: we are in communicateWithServer");
        String serverResponse = in.readLine();
        //System.out.println("######### DEBUG: Server response1: "+serverResponse);

        if ("Welcome to ChatApp. Please log in or register.".equals(serverResponse)){
            System.out.println(serverResponse);
        }

        if ("Enter 'login' to log in or 'register' to register:".equals(serverResponse)) {
            System.out.println(serverResponse);

            String choice = userInput.readLine();
            out.println(choice);
            out.flush();

            if ("login".equalsIgnoreCase(choice)) {
                System.out.println("Enter your username: ");
                String username = userInput.readLine();
                out.println(username);
                out.flush();
                System.out.println("Enter your password: ");
                String password = userInput.readLine();
                out.println(password);
                out.flush();

                serverResponse = in.readLine();
                System.out.println(serverResponse); // Print server response
            } else if ("register".equalsIgnoreCase(choice)) {
                System.out.println("Enter your desired username: ");
                String username = userInput.readLine();
                out.println(username);
                out.flush();
                System.out.println("Enter your password: ");
                String password = userInput.readLine();
                out.println(password);
                out.flush();

                serverResponse = in.readLine();
                System.out.println(serverResponse); // Print server response
            } else {
                System.out.println("Invalid choice. Connection closed.");
            }
        } else {
            System.out.print("");
        }
    }

    public static void main(String[] args) {
        if (args.length == 1) {
            try {
                SERVER_PORT = Integer.parseInt(args[0]); // Assigning a new SERVER_PORT value
            } catch (NumberFormatException e) {
                System.err.println("Invalid SERVER_PORT number. Using the default SERVER_PORT: " + SERVER_PORT);
            }
        } else {
            System.err.println("Usage: java ChatClient <SERVER_PORT>");
            System.err.println("Using the default SERVER_PORT: " + SERVER_PORT);
        }
        System.out.println("Connected to chat server on PORT: " + SERVER_PORT);

        try {
            Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            // Generate the client's secret key for encryption
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            clientSecretKey = keyGenerator.generateKey();
            encodedClientKey = Base64.getEncoder().encodeToString(clientSecretKey.getEncoded());
            System.out.println("############# DEBUG - CLIENT GENERATED ENCODED KEY: "+encodedClientKey); // ########### DEBUG: CLIENT'S ENCODED SECRET KEY

            // 1. Client sends its client encoded key to server ############################
            out.println(encodedClientKey); // Send the client encoded key to the server
            System.out.println("############# DEBUG - SENT CLIENT ENCODED KEY: "+encodedClientKey);

            // 2. Client receives the server's server encoded key and saves it ############################
            // IMPORTANT: RECEIVING SERVER KEY
            String encodedServerKey = in.readLine(); // received ServerSecretKey (encoded)
            System.out.println("############# DEBUG - RECEIVED SERVER ENCODED KEY : "+encodedServerKey); // DEBUG

            // Prompt the user for their preferred username
            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
            System.out.print("Enter your preferred chat nickname: ");
            String username = userInput.readLine();
            out.println(username);
            out.flush();

            boolean ranOnce = false;
            if(ranOnce != true){
                communicateWithServer(out, in, userInput);
                ranOnce = true;
            }

            // Start a thread to read and display messages from the server
            Thread readerThread = new Thread(() -> {
                try {
                    String serverResponse;
                    while ((serverResponse = in.readLine()) != null) {
                        // Check is serverResponse is an encrypted message
                        if (serverResponse.startsWith("ENCRYPTED:///")) {
                            String[] formattedResponse = serverResponse.split("///");
                            //System.out.println("Formatted server response [0]: "+formattedResponse[0]);
                            //System.out.println("Formatted server response [1]: "+formattedResponse[1]);
                            System.out.println(decrypt(formattedResponse[1], encodedServerKey)); // decrypt it using encodedServerKey
                            //System.out.println(getCurrentTimestamp() + " " + decrypt(formattedResponse[1], encodedServerKey));
                        } else {
                            System.out.println(serverResponse); // Message is not encrypted, print it as is
                        }

                    }
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                         BadPaddingException | InvalidKeyException e) {
                    throw new RuntimeException(e);
                }
                System.out.print(username + ": ");
            });
            readerThread.start();

            // Message sending logic
            String message;
            while (true) {
                message = userInput.readLine();
                //System.out.println("### DEBUG - Client msg (client-side): "+message);
                if (message.equalsIgnoreCase("exit")) {
                    break;
                } else {
                    // Encrypt the message before sending
                    String encryptedMessage = encrypt(message, clientSecretKey);
                    //System.out.println("### DEBUG - Client encrypted msg (client-side): "+encryptedMessage);
                    out.println(encryptedMessage);
                    out.flush();
                }
            }
            socket.close(); // Closing the socket when done with the transfer

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private static String encrypt(String message, SecretKey clientSecretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, clientSecretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String encryptedMessage, String encodedServerKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        byte[] keyBytes = Base64.getDecoder().decode(encodedServerKey);
        SecretKey secretKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

}
