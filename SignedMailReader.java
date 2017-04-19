package com.crypto.mail.signature;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.mail.BodyPart;
import javax.mail.Folder;
import javax.mail.Message;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.Store;

public class SignedMailReader {
	
	//authentication
	public static String username = "**********@gmail.com";
	public static String password = "**********";
	
	public static void main(String[] args) throws Exception {
				
		//crypto variables
		String hashAlgorithm = "SHA-512";
		String publicKeyAlgorithm = "RSA";
				
		byte[] alicePublicKey = {48, -126, 1, 34, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 3, -126, 1, 15, 0, 48, -126, 1, 10, 2, -126, 1, 1, 0, -95, -31, 108, -69, 59, 77, -11, 43, -116, 118, 74, -75, -123, 117, -44, 39, 121, 89, 67, 10, -57, -27, 25, 110, -86, 28, -57, -116, 119, -93, 40, -84, 123, -105, 30, -66, 69, -67, 104, 121, -68, 102, 71, -44, 87, -3, -45, -21, -88, 59, 64, 88, -124, -20, -90, 21, 52, -115, 125, -33, 93, 0, 43, -67, -6, 76, 22, -123, 88, -91, -43, 63, 32, 74, 107, 12, -69, -80, -80, 124, -79, 16, 0, -55, -113, 84, -43, 17, -15, 26, -29, -2, 124, 0, -26, 25, 97, -64, 32, -22, 99, 91, 91, -42, -85, 93, -52, 76, -71, -53, 45, 38, 52, -28, -6, 92, 108, -105, -84, -53, 29, 80, 60, -98, -103, 63, 71, 3, -30, -118, -94, 76, 39, 46, -112, -65, 14, 112, -82, -38, 31, 20, -10, -53, 101, -52, 37, 3, -20, -84, -83, -128, -88, 27, -109, -5, 69, -18, -42, 123, -31, 85, -101, -4, -93, -95, 13, -8, 49, -120, 90, -42, -102, -73, 85, -59, -56, 69, -79, 106, 32, 51, -77, -3, 108, -101, -99, -96, 33, 63, -66, -82, 16, 60, -45, 52, -125, -114, -23, -84, -47, -19, 75, -24, 67, -62, 34, 124, -18, -38, 7, -24, -126, 123, 80, 34, 104, -107, -85, -11, -6, -8, -81, -59, -121, 81, 99, -90, -27, 0, 80, 30, -122, 71, 112, 116, 114, -79, -45, 3, -40, -119, 119, -61, 19, 16, -95, -28, 64, -73, -87, 4, 62, -70, 54, 17, 2, 3, 1, 0, 1};
		
		Message[] messages = retrieveMails();
		
	    for (int i = 0; i < messages.length; i++) {
	    	
	    	Message message = messages[i];
	    	
	    	Multipart multipart = (Multipart) message.getContent();
	    	BodyPart bodyPart = multipart.getBodyPart(0);
	    	
	    	String content = bodyPart.getContent().toString();
	    	String signature = ((Multipart) message.getContent()).getBodyPart(1).getContent().toString();
	    	
	    	//received message hash. this will be compared with received signature.
			MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
			md.update(content.getBytes());
			byte[] expectedHash = md.digest();
			String expectedHashString = new String(Base64.getEncoder().encode(expectedHash));
			
			try{
				//decrypt signature with Alice public key
				byte[] decodedSignature = Base64.getDecoder().decode(signature.getBytes());
				Cipher publicKeyEncryption = Cipher.getInstance(publicKeyAlgorithm);
				publicKeyEncryption.init(Cipher.DECRYPT_MODE, KeyFactory.getInstance(publicKeyAlgorithm).generatePublic(new X509EncodedKeySpec(alicePublicKey)));
				byte[] decryptedHash = publicKeyEncryption.doFinal(decodedSignature);
				String decryptredHashString = new String(Base64.getEncoder().encode(decryptedHash));
				
				if(decryptredHashString.equals(expectedHashString)){
					System.out.println("Signature is valid...");
				}
				else{
					throw new Exception();
				}
			}
			catch(Exception ex){
				//invalid signature content might cause to throw exception while decrypting
				System.out.println("Invalid signature detected!...");
			}
	    	
	    }
		
	}
	
	public static Message[] retrieveMails() throws Exception{
		Properties properties = new Properties();
		properties.put("mail.store.protocol", "imaps");
	    Session emailSession = Session.getDefaultInstance(properties);
	    
	    Store store = emailSession.getStore("imaps");
	    store.connect("imap.gmail.com", username, password);
	    
	    Folder emailFolder = store.getFolder("INBOX");
	    emailFolder.open(Folder.READ_ONLY);
	    
	    Message[] messages = emailFolder.getMessages();
	    
	    emailFolder.close(false);
	    store.close();
	    
	    return messages;
	}

}
