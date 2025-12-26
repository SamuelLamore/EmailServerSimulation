import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class EmailReader {
	// Each email is encoded as 5 lines of encrypted text (the sender's name, the title, the date/time, the body, and the signature)
	// Followed by 1 blank line
	static final int LINES_PER_EMAIL = 6;
	
	private static Scanner jumpToEmail(int emailNum, File inboxFile) throws FileNotFoundException {
		Scanner inbox = new Scanner(inboxFile);
		
		//Given an index value of an email, skip over that many lines to reach it
		for (int i = 0; i < emailNum * LINES_PER_EMAIL; i++) {
			if (inbox.hasNextLine()) {
				inbox.nextLine();
			} else {
				return null;
			}
		}
		
		return inbox;
	}
	
	private static Email decryptEmail(int emailNum, File inboxFile, PrivateKey key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, FileNotFoundException, SignatureException, InvalidKeySpecException {
		Email email = new Email();
		// Get a scanner object already set to the correct email
		Scanner inbox = jumpToEmail(emailNum, inboxFile);
		
		if (inbox == null) {
			return null;
		}
		
		//decrypt first line, thats the sender
		email.setSender(CipherHandling.decryptString(inbox.nextLine(), key));
		
		//decrypt second line, thats the title
		email.setTitle(CipherHandling.decryptString(inbox.nextLine(), key));
		
		//decrypt third line, thats the date/time
		email.setDate(CipherHandling.decryptString(inbox.nextLine(), key));
		
		//decrypt fourth line, thats the body
		email.setBody(CipherHandling.decryptString(inbox.nextLine(), key));
		
		//store the signature
		email.setSignature(inbox.nextLine());
		
		//skip empty filler line
		if (inbox.hasNextLine()) {
			inbox.nextLine();
		}
		inbox.close();
		
		return email;
	}
	
	
	//List the most recent 50 emails
	public static void listEmails(File inbox) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, FileNotFoundException, SignatureException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		Email email;
		int emailNum = 0;
		while ((email = decryptEmail(emailNum, inbox, AccountHandling.getCurUserPrivKey())) != null && emailNum < 50) {
					

			System.out.println("\n" + (emailNum+1) + ". " + email.getTitle());
			System.out.println("   From " + email.getSender() + " on " + email.getDate());
			//verify signature
			if (!email.verify()) {
				System.out.println("!!!\nThis email's signature could not be verified. The sender may not be who they said they are.\n!!!");
			}
			
			emailNum++;
		}
	}
	
	
	public static void readEmails() throws FileNotFoundException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, SignatureException, InvalidAlgorithmParameterException {
		//Fetch curUser's inbox file
		String inboxPath = "cs492_email_database/" + AccountHandling.getCurUser() + ".txt";
		File inbox = new File(inboxPath);
		// Skip if there are no emails
		if (inbox.exists() && inbox.length() > 0) {
			//List all the emails
			listEmails(inbox);
							
			
			// Let user pick which email to open
			System.out.print("Choose a number to pick an email (Type '0' to return): ");
			Scanner kb = new Scanner(System.in);
			int emailToRead = kb.nextInt();
			
			if (emailToRead > 0) {
				Email email = decryptEmail(emailToRead-1, inbox, AccountHandling.getCurUserPrivKey());
				
				// If it exists, display the full email
				if (email == null) {
					System.out.println("That email doesn't exist.");
				} else {
					System.out.println(email.getTitle());
					System.out.println("From " + email.getSender() + " on " + email.getDate() + "\n");
					System.out.println(email.getBody());
				}
				
				
				System.out.print("\nPress Enter to return");
				kb.nextLine(); // 2 calls are necessary here. The first one gets immediately consumed when you enter the email number
				kb.nextLine(); // The second one stalls the program until the user hits enter.
			} else if (emailToRead == 0) {
				return;
			}
		} else {
			System.out.println("You do not have any emails.\n");
		}
		
	}
}
