import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CipherHandling {
	// A lot of method overloading here
	// The 3 methods are for encrypting, decrypting, and signature verification
	// The different versions of each method allow you to input both Strings and byte arrays, and to receive either as inputs
	// Removes need for handling data conversions manually
	
	public static String encryptString(String data, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);		
    	byte[] encryption = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    	return Base64.getEncoder().encodeToString(encryption);
	}
	
	public static String encryptString(byte[] data, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);		
		byte[] encryption = cipher.doFinal(data);
		return Base64.getEncoder().encodeToString(encryption);
	}
	
	public static byte[] encryptBytes(String data, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);		
    	return cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
	}
	
	public static byte[] encryptBytes(byte[] data, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);		
    	return cipher.doFinal(data);
	}
	
	public static String decryptString(String data, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
    	cipher.init(Cipher.DECRYPT_MODE, key);
    	
    	byte[] encryptedBytes = Base64.getDecoder().decode(data);
    	byte[] decrypted = cipher.doFinal(encryptedBytes);    	
    	return new String(decrypted, StandardCharsets.UTF_8);
	}
	
	public static String decryptString(byte[] data, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
    	cipher.init(Cipher.DECRYPT_MODE, key);
    	byte[] decrypted = cipher.doFinal(data);
    	return new String(decrypted, StandardCharsets.UTF_8);
	}
	
	public static byte[] decryptBytes(String data, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
    	cipher.init(Cipher.DECRYPT_MODE, key);
    	byte[] encryptedBytes = Base64.getDecoder().decode(data);
    	byte[] decrypted = cipher.doFinal(encryptedBytes);
    	return decrypted;
	}
	
	public static byte[] decryptBytes(byte[] data, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
    	cipher.init(Cipher.DECRYPT_MODE, key);
    	byte[] decrypted = cipher.doFinal(data);
    	return decrypted;
	}
	
	public static boolean verifySignature(byte[] msg, byte[] sig, PublicKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(key);
        s.update(msg);
    	
    	return s.verify(sig);
	}
	
	public static boolean verifySignature(String msg, String sig, PublicKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(key);
        s.update(msg.getBytes(StandardCharsets.UTF_8));
    	
    	return s.verify(Base64.getDecoder().decode(sig));
	}
	
	public static boolean verifySignature(byte[] msg, String sig, PublicKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(key);
        s.update(msg);
    	
        return s.verify(Base64.getDecoder().decode(sig));
	}
	
	public static boolean verifySignature(String msg, byte[] sig, PublicKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(key);
        s.update(msg.getBytes(StandardCharsets.UTF_8));
    	
    	return s.verify(sig);
	}
}
