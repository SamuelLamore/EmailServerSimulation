import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AccountHandling {
	private static String curUser = "";
	// needed to decrypt RSA private key
	private static String curPassword = "";
	
	
	// Finds user's encrypted private key and decrypts it
	public static PrivateKey getCurUserPrivKey() throws NoSuchAlgorithmException, InvalidKeySpecException, FileNotFoundException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException {
    	FileInputStream keys = new FileInputStream("cs492_email_database/private.key");
    	FileInputStream keyDecryption = new FileInputStream("cs492_email_database/private_aes.key");
    	Scanner file = new Scanner(keys);
    	Scanner fileDecryptor = new Scanner(keyDecryption);
    	String privKey = "";
    	
    	//Iterate through file to find the encrypted private key
    	while (file.hasNext()) {
    		if (file.next().equals("\"" + getCurUser() + "\"")) {
    			privKey = file.next();
    			break;
    		} else {
    			file.next();
    		}
    	}
    	file.close();
    	
    	if (privKey.equals("")) {
    		fileDecryptor.close();
    		return null;
    	}
    	
    	
    	String salt = "";
    	String iv = "";
    	//Iterate through file to find the salt and iv needed to generate aes key to decrypt the encrypted private key
    	while (fileDecryptor.hasNext()) {
    		if (fileDecryptor.next().equals("\"" + getCurUser() + "\"")) {
    			salt = fileDecryptor.next();
    			iv = fileDecryptor.next();
    			break;
    		} else {
    			fileDecryptor.next();
    			fileDecryptor.next();
    		}
    	}
    	fileDecryptor.close();
    	
    	if (salt.equals("")) {
    		return null;
    	}
    	
    	//Decrypt user's private key
    	byte[] saltBytes = Base64.getDecoder().decode(salt);
    	byte[] ivBytes = Base64.getDecoder().decode(iv);
    	byte[] keyBytes = Base64.getDecoder().decode(privKey);
    	
    	//Retrieve the AES key
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(getCurPassword().toCharArray(), saltBytes, 65536, 256);
        SecretKeySpec aesKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    	
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        byte[] decryptedKey = cipher.doFinal(keyBytes);
        
		
		//Convert user's private key string into a proper key object that can be used
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decryptedKey);
    	KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    	return keyFactory.generatePrivate(keySpec);
	}
	
	
	//Iterate through public key file to find a given user's public key
	public static PublicKey getPubKeyByUser(String user) throws NoSuchAlgorithmException, InvalidKeySpecException, FileNotFoundException {
    	FileInputStream keys = new FileInputStream("cs492_email_database/public.key");
    	Scanner file = new Scanner(keys);
    	String pubKey = "";
    	
    	while (file.hasNext()) {
    		if (file.next().equals("\"" + user + "\"")) {
    			pubKey = file.next();
    			break;
    		} else {
    			file.next();
    		}
    	}
    	file.close();
    	
    	if (pubKey.equals("")) {
    		return null;
    	}
		
    	//Convert user's public key string into a proper key object that can be used
		byte[] keyBytes = Base64.getDecoder().decode(pubKey);
    	X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    	KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    	return keyFactory.generatePublic(spec);
	}
	
	
	public static PublicKey getCurUserPubKey() throws NoSuchAlgorithmException, InvalidKeySpecException, FileNotFoundException {
    	return getPubKeyByUser(getCurUser());
	}
	
	
	public static String getCurUser() {
		return curUser;
	}
	
	private static void setCurUser(String user) {
		curUser = user;
	}
	
	public static String getCurPassword() {
		return curPassword;
	}
	
	private static void setCurPassword(String pass) {
		curPassword = pass;
	}
    
    
    public static boolean isUsernameTaken(String username) throws FileNotFoundException {
    	File passFile = new File("cs492_email_database/passwords.txt");
    	if (!passFile.exists()) {
    		return false;
    	}
    	FileInputStream keys = new FileInputStream("cs492_email_database/passwords.txt");
    	Scanner file = new Scanner(keys);
    	
    	//iterate through all the username + password combo entries
    	while (file.hasNext()) {
    		//if username matches, then it is taken
    		if (file.next().equals("\"" + username + "\"")) {
    			file.close();
    			return true;
    		} else {
    			file.next();
    		}
    	}
    	file.close();
    	return false;
    }
    
	
    private static String[] setUserAndPass() {
		try {
			FileWriter passFile = new FileWriter("cs492_email_database/passwords.txt", true);
			FileWriter saltFile = new FileWriter("cs492_email_database/salts.txt", true);
			Scanner keyboard = new Scanner(System.in);
			
			String username;
			
			//Only allow letters and numbers for username (and only 1 word)
			while (true) {
				System.out.print("Choose a username: ");
			    username = keyboard.nextLine();
			    if (username.matches("[a-zA-Z0-9]+")) {
			    	//check if username is already taken
			    	if (isUsernameTaken(username)) {
			    		System.out.println("This username is already taken.");
			    	} else {			    		
			    		break;
			    	}
			    } else {
			        System.out.println("Invalid username. Only letters and numbers are allowed, no spaces.");
			    }
			}
			
			
			System.out.print("Choose a password: ");
			String password = keyboard.nextLine();
			
			//Generate salt to hash the password with
	        SecureRandom sr = SecureRandom.getInstanceStrong();
	        byte[] salt = new byte[16];
	        sr.nextBytes(salt);
			
			// Hash the password instead of storing it in plain text
			MessageDigest hashing = MessageDigest.getInstance("SHA-256");
			hashing.update(salt);
			byte[] hash = hashing.digest(password.getBytes());
			
			saltFile.write("\"" + username + "\" " + Base64.getEncoder().encodeToString(salt) + "\n");
			passFile.write("\"" + username + "\" " + Base64.getEncoder().encodeToString(hash) + "\n");
			
			passFile.close();
			saltFile.close();
			
			String[] userData = new String[2];
			userData[0] = username;
			userData[1] = password;
			return userData;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
    public static void createAccount() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    	//[0] = username, [1] = password
		String userData[] = setUserAndPass();
		
		Server.setUpAccount(userData[0], userData[1]);
	}
    
    
    private static String getSaltFromUsername(String username) throws FileNotFoundException {
    	File saltFile = new File("cs492_email_database/salts.txt");
    	if (saltFile.exists()) {    		
    		FileInputStream salts = new FileInputStream("cs492_email_database/salts.txt");
    		Scanner file = new Scanner(salts);
    		
    		while (file.hasNext()) {
    			if (file.next().equals("\"" + username + "\"")) {
    				String salt = file.next();
    				file.close();
    				return salt;
    			} else {
    				file.next();
    			}
    		}
    		
    		file.close();
    	}
    	return null;
    }
    
    
    private static String getPassHashFromUsername(String username) throws FileNotFoundException {
    	File passFile = new File("cs492_email_database/passwords.txt");
    	if (passFile.exists()) {
    		FileInputStream hashes = new FileInputStream("cs492_email_database/passwords.txt");
    		Scanner file = new Scanner(hashes);
    		
    		while (file.hasNext()) {
    			if (file.next().equals("\"" + username + "\"")) {
    				String hash = file.next();
    				file.close();
    				return hash;
    			} else {
    				file.next();
    			}
    		}
    		
    		file.close();
    	}
    	return null;
    }
    
    
    //Simple authentication protocol:
    	// User sends {nonce}_Server to server
    	// Server responds with [nonce]_Server
    private static boolean authenticateWithServer() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, SignatureException {
    	//Send challenge nonce to server, encrypted with server's public key

    	//Generate a 16-byte nonce
    	SecureRandom secRandom = new SecureRandom();
    	byte[] nonce = new byte[16];
    	secRandom.nextBytes(nonce);
    	
    	
    	//Encrypt nonce with server's public key
    	Cipher cipher = Cipher.getInstance("RSA");
    	cipher.init(Cipher.ENCRYPT_MODE, Server.getPubKey());
    	byte[] encryptedNonce = cipher.doFinal(nonce);
    	
    	byte[] challengeResponse = Server.challenge(encryptedNonce);
    	
    	//Make sure the server responds with a signature of the nonce
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(Server.getPubKey());
        sig.update(nonce);
    	
    	return sig.verify(challengeResponse);
    }
    
	
    
    public static boolean logIn() throws NoSuchAlgorithmException, FileNotFoundException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, SignatureException {
    	boolean success = false;
    	Scanner keyboard = new Scanner(System.in);
    	
    	
    	System.out.println("Attempting Authentication...");
    	
    	//authenticate
    	if (!authenticateWithServer()) {
    		//If authentication fails
    		System.out.println("Authentication Failed: The Server's Authenticity Could Not Be Confirmed");
    		return success;
    	} else {
    		System.out.println("Authentication Succeeded.");
    	}
    	
    	
		System.out.print("Enter a username: ");
		String username = keyboard.nextLine();
		System.out.print("Enter a password: ");
		String password = keyboard.nextLine();
		
		// If salt or hash are null, then the username wasn't found and success remains false
		String salt = getSaltFromUsername(username);
		String hash = getPassHashFromUsername(username);
		if (salt != null && hash != null) {
			MessageDigest hashing = MessageDigest.getInstance("SHA-256");
			hashing.update(Base64.getDecoder().decode(salt));
			byte[] tmpHash = hashing.digest(password.getBytes());
			String newHash = Base64.getEncoder().encodeToString(tmpHash);

	    	if (hash.equals(newHash)) {
	    		success = true;
	    	}
		}
		
    	if (success) {
    		System.out.println("You have logged in to " + username + "'s inbox");
    		setCurUser(username);
    		setCurPassword(password);
    	} else {
    		System.out.println("Incorrect Username or Password.");
    	}
    	
    	return success;
    }
}
