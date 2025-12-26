import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Server {
	public static final String pubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6BASVE/kT0mll0xMhTvM6m0zj4XZV/lk4Voc+RAoAPHbpRtlSm36mUwZGTjSG3ejTyz1FUO6gPcX1V4JBsVS2JFyzwqP1i+taiBhyo+pFpOGPxVsflwQ6VWuYp6o0HsPgEaGC4tNYFNt8W4J+YgSJ8Gp7J6sf7HgLT2h9/SCmva5nZ+q8wvTkXJjqJOF0bcU65+ntZM/xo34GpXXp3zWCxJ+0KYKWf0i29iXamsnLe+MQPRlWzflxynmerbKjm0L0kNx4nrMQsyRlZZiK6uXg9GzpiLRgH/13qnYUqfvc4/OPyJNU7xMFlslChHAWJD+mZ8U0+vHw/DgyxYU8SsLTQIDAQAB";
	// In a real environment, the private key shouldn't be stored like this
	private static final String privKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDoEBJUT+RPSaWXTEyFO8zqbTOPhdlX+WThWhz5ECgA8dulG2VKbfqZTBkZONIbd6NPLPUVQ7qA9xfVXgkGxVLYkXLPCo/WL61qIGHKj6kWk4Y/FWx+XBDpVa5inqjQew+ARoYLi01gU23xbgn5iBInwansnqx/seAtPaH39IKa9rmdn6rzC9ORcmOok4XRtxTrn6e1kz/GjfgaldenfNYLEn7QpgpZ/SLb2Jdqayct74xA9GVbN+XHKeZ6tsqObQvSQ3HiesxCzJGVlmIrq5eD0bOmItGAf/XeqdhSp+9zj84/Ik1TvEwWWyUKEcBYkP6ZnxTT68fD8ODLFhTxKwtNAgMBAAECggEAGY81mZwwCwyTRLoGXpFS1UogSPFG2kHxesGcWdFN+qao2MNO8XbyCELhq82+lIBlmBGdT9GFH/G3KgzApUKECK7ibIvfAkn/iWYWJ0OR7dbjTRzstXEp+q0xdxK/CLFZKHl8B5b494BQ5mvGhPmX+FGEB/gFC0554Lm+VmtTnEIVRyPSjZnbjeATejjjT1zESRETtaKbIbvVlZF9vC3fThL0J877GRmGAPpwxFc0OP8y7dfKKfYqidyKfUOSsEmbiKmG3u0PcVDnWkoSY49krSz4czRt9D2mmSVG5YgPPBxeuoPT1T1WkLcvOByuR4WnLE6yBRwdsiA0dZCrVrD0GQKBgQDw4jXpI44YbChRg9AnN+7z+SPGUfvi4Spq0Rd/7ag3wejnvXDyNgZ2u7dqI+1UckloOCF3Qg6+qzG1ZZtzXnumdmeMSUEODvw+qZqy/9RqMoegQYCo/c0ld2zUct9Chu4BvRCBKnJGNmz2HFC0FllJWWMDPS/S5967069Pn1lFNQKBgQD2oCd5STQd1pzuyFpxd+sOoFCaPwqktfj1G33sj3RCOAX7vCk1Lxq17oPefL8BvpYoQN6iLNUd7DQLmidtW7b9hgaGggZLu4UKxNl2YtQyySGofk5UW5gIysJoql2D8lRUby6cISlUnY5yMlJWOVX62oqhmqFvYEXMD+mbZTDouQKBgQCDJZXWbc4yS8iTwOE2SQSm/hDVK9OozZCLgXV66Ah6+u70JLb2mCVixYbxmcff/y0qOc02oddnRcuViFFfOaS2l6Z+wW9S2SPKdgrMw+6BNyuSO7dxymTDrkapUDVvggjZF3eB63s18PHX+MiTk8te3PTEUa7U8/rXZkP/ZLF0tQKBgCSXxsOcNPtoaIiVebX0URAugUchq3ac+X+EwL5k2p8oqNqdJJAbmR79cNuGLuEXYjg+x8nQVR7HeUFvcgIr5Y7gX/99M2nxPOBILOv/5fRTG4dglka2AGztiML25EE7p3+Pr57C3NsNNaGEDet1PmimHIO16dYYtsJ8afEApq0hAoGBANsQX7Los02U4dSBELinZizIXY2KvHhQ5bZzJbZgDCMUrKMv3zbAhY6owh55VMZZly5o8tQGaKwMZFIgQdxw97Z079ftfWdynMW4P6h2I1WNR9papryg3UHP05Y0GldEGFoT3uypdVYVPFr06YYVAeFWFO6QTazzpL9Kzjt3dq3z";

	public static byte[] challenge(byte[] challenge) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {
		// Use the server's private key to decrypt the challenge
		Cipher cipher = Cipher.getInstance("RSA");
    	cipher.init(Cipher.DECRYPT_MODE, Server.getPrivKey());
    	byte[] nonce  = cipher.doFinal(challenge);
    	
    	// Sign the decrypted challenge
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(Server.getPrivKey());
        sig.update(nonce);
    
    	//Returns signed version of the nonce
		return sig.sign();
	}
	
	
	public static void setUpAccount(String username, String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		//RSA Key Generation & Storing
		KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
		rsaGenerator.initialize(2048);
		KeyPair pair = rsaGenerator.generateKeyPair();
		
		FileWriter pubFile = new FileWriter("cs492_email_database/public.key", true);
		FileWriter privFile = new FileWriter("cs492_email_database/private.key", true);
		
		//Retrieve public and private keys, and encode them as strings for storing
		PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();
        String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		
        //Use password to AES encrypt private key
        
        //Convert password to key
        byte[] salt = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeySpec aesKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        
        //Encrypt private RSA key with AES key
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        String encryptedPrivKey = Base64.getEncoder().encodeToString(cipher.doFinal(privateKey.getEncoded()));
        
		pubFile.write("\"" + username + "\" " + publicKeyString + "\n");
		privFile.write("\"" + username + "\" " + encryptedPrivKey + "\n");
		
		pubFile.close();
		privFile.close();
		
		//Store the salt and iv for the private key encryption
		FileWriter aesFile = new FileWriter("cs492_email_database/private_aes.key", true);
		aesFile.write("\"" + username + "\" " + Base64.getEncoder().encodeToString(salt) + " " + Base64.getEncoder().encodeToString(iv) + "\n");
		aesFile.close();
		
		System.out.println("Account created successfully.");
	}
	
	
	
	private static PrivateKey getPrivKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
    	//Convert server's private key string to a proper key object that can be used
		byte[] keyBytes = Base64.getDecoder().decode(privKey);
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
    	KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    	return keyFactory.generatePrivate(spec);
	}
	
	
	public static PublicKey getPubKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		//Convert server's public key string to a proper key object that can be used
		byte[] keyBytes = Base64.getDecoder().decode(pubKey);
    	X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    	KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    	return keyFactory.generatePublic(spec);
	}
	
	
	public static void sendEmail(String recipient, String sender, String title, String date, String email, byte[] emailSig) throws IOException {
		File inbox = new File("cs492_email_database/" + recipient + ".txt");
		
		// New emails are added to the top, so we need to copy the prior contents of the inbox, so we can write it after the new email
	    String olderEmails = "";
	    if (inbox.exists()) {
	    	olderEmails = new String(Files.readAllBytes(inbox.toPath()), StandardCharsets.UTF_8);
	    }

	    FileWriter inboxWriter = new FileWriter(inbox, false);
    	inboxWriter.write(sender + "\n");
    	inboxWriter.write(title + "\n");
    	inboxWriter.write(date + "\n");
    	inboxWriter.write(email + "\n");
    	inboxWriter.write(Base64.getEncoder().encodeToString(emailSig) + "\n");
    	if (!olderEmails.isEmpty()) {
    		inboxWriter.write("\n" + olderEmails);
    	}
    	inboxWriter.close();
	}
	
}
