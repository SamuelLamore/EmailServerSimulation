import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

public class Email {
	private String sender;
	private String title;
	private String date;
	private String body;
	private String signature;
	private boolean verified = false;
	
	
	public Email() {
		
	}
	
	public Email(String sender, String title, String date, String body) {
		setSender(sender);
		setTitle(title);
		setDate(date);
		setBody(body);
	}
	
	
	public String getSender() {
		return sender;
	}
	
	public String getTitle() {
		return title;
	}
	
	public String getDate() {
		return date;
	}
	
	public String getBody() {
		return body;
	}
	
	public String getSignature() {
		return signature;
	}
	
	
	public void setSender(String sender) {
		this.sender = sender;
	}
	
	public void setTitle(String title) {
		this.title = title;
	}
	
	public void setDate(String date) {
		this.date = date;
	}
	
	public void setBody(String body) {
		this.body = body;
	}
	
	public void setSignature(String signature) {
		this.signature = signature;
	}
	
	public boolean verify() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, FileNotFoundException {
		//the signature is of the email body. So we get the sender's public key to check the signature against the email body
		return this.verified = CipherHandling.verifySignature(getBody(), getSignature(), AccountHandling.getPubKeyByUser(getSender()));
	}
}
