import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class EmailWriter {
	public static void encryptAndSendEmail(String recipient, String title, String body) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, SignatureException, IOException, InvalidAlgorithmParameterException {
		PublicKey pubKey = AccountHandling.getPubKeyByUser(recipient);
		
		//Gets the time that the email is being sent, and formats it as a string
        LocalDateTime currentDateTime = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        String dateTime = currentDateTime.format(formatter);
		
		//Encrypt title, time, and body with the recipient's public key
    	String encryptedTitle = CipherHandling.encryptString(title, pubKey);
    	String encryptedDate = CipherHandling.encryptString(dateTime, pubKey);
    	String encryptedBody = CipherHandling.encryptString(body, pubKey);
    	
		//Sign body with current user's (sender's) private key
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(AccountHandling.getCurUserPrivKey());
		sig.update(body.getBytes(StandardCharsets.UTF_8));
		byte[] signedEmail = sig.sign();
    	
    	//Also encrypt the sender's name with the recipient's public key, so that they know who it's from and what public key to use to verify the signature
    	String encryptedSender = CipherHandling.encryptString(AccountHandling.getCurUser(), pubKey);
		
		
		//Run server method to send to inbox
    	Server.sendEmail(recipient, encryptedSender, encryptedTitle, encryptedDate, encryptedBody, signedEmail);
	}
	
	public static void writeEmail() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, SignatureException, IOException, InvalidAlgorithmParameterException {
		Scanner keyboard = new Scanner(System.in);
		String recipient;
		while (true) {
			System.out.print("Enter a user to send to: ");
			recipient = keyboard.next();
			// Make sure the account exists
			if (AccountHandling.isUsernameTaken(recipient)) {
				break;
			}
			System.out.println("A user by that name does not exist.");
		}
		keyboard.nextLine(); // Prevents the newline character automatically skipping the title input
		
		//Enter Email Title
		System.out.println("Enter a title for your email:");
		String title = keyboard.nextLine();
		
		//Enter Email Body
		System.out.println("Write your email:");
		String body = keyboard.nextLine();
		
		
		//Confirm sending
		System.out.print("Are you sure you want to send \"" + title + "\" to " + recipient + "? (Y/N): ");
		boolean repeat = false;
		do {			
			String confirmation = keyboard.next();
			if (confirmation.toLowerCase().equals("y") || confirmation.toLowerCase().equals("yes")) {
				System.out.println("Sending to " + recipient + "...");
				repeat = false;
				encryptAndSendEmail(recipient, title, body);
			} else if (confirmation.toLowerCase().equals("n") || confirmation.toLowerCase().equals("no")) {
				System.out.println("Returning...");
				return;
			} else {
				System.out.print("Please respond with 'Y' for yes or 'N' for no: ");
				repeat = true;
			}
		} while (repeat);
		System.out.println("Email Sent.");
	}
}
