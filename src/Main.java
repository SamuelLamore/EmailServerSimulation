import java.util.InputMismatchException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

public class Main {
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, SignatureException, InvalidAlgorithmParameterException {
		// Immediately create folder for the data if it doesn't already exist
		File folder = new File("cs492_email_database");
		if (!folder.exists()) {
			folder.mkdirs();
		}
		
		Scanner keyboard = new Scanner(System.in);
		
		//First set of options
		while (true) {
		    System.out.print("1. Log in\n2. Create Account\n3. Exit\nChoose an option: ");
		    boolean success = false;
		    try {
		        int option = keyboard.nextInt();
		        switch (option) {
		            case 1:
		                success = AccountHandling.logIn();
		                break;
		            case 2:
		                AccountHandling.createAccount();
		                break;
		            case 3:
		                keyboard.close();
		                System.exit(0);
		                break;
		            default:
		                System.out.println("Invalid option. Please enter 1, 2, or 3.");
		        }
		        
		        //If user is logged in, go to next set of options
				if (success) {
					break;
				}
		    } catch (InputMismatchException e) {
		        System.out.println("Invalid input. Please enter a number.");
		        keyboard.nextLine();
		    }
		}
		
		
		//Options once you're logged in
		while (true) {
			System.out.println("Welcome " + AccountHandling.getCurUser());
			System.out.print("1. Write Email\n2. Read Email\n3. Exit\nChoose an option: ");
			try {
				
				int option = keyboard.nextInt();
				switch (option) {
					case 1:
						//write email
						EmailWriter.writeEmail();
						break;
					case 2:
						//read email
						EmailReader.readEmails();
						break;
					case 3:
						keyboard.close();
						System.exit(0);
						break;
		            default:
		                System.out.println("Invalid option. Please enter 1, 2, or 3.");
				}
			} catch (InputMismatchException e) {
		        System.out.println("Invalid input. Please enter a number.");
		        keyboard.nextLine();
		    }
		}
	}
}
