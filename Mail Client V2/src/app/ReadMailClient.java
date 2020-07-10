package app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;
import org.w3c.dom.Document;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import model.keystore.KeyStoreReader;
import model.mailclient.MailBody;
import support.MailHelper;
import support.MailReader;
import util.Base64;
import util.DataUtil;
import util.GzipUtil;

public class ReadMailClient extends MailClient {

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;
	
	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, MessagingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        // Build a new authorized API client service.
        Gmail service = getGmailService();
        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
        
        String user = "me";
        String query = "is:unread label:INBOX";
        
        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
        for(int i=0; i<messages.size(); i++) {
        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
        	
        	MimeMessage mimeMessage;
			try {
				
				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
				
				System.out.println("\n Message number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");
				
				mimeMessages.add(mimeMessage);
	        
			} catch (MessagingException e) {
				e.printStackTrace();
			}	
        }
        
        System.out.println("Select a message to decrypt:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	        
	    String answerStr = reader.readLine();
	    Integer answer = Integer.parseInt(answerStr);
	    
		MimeMessage chosenMessage = mimeMessages.get(answer);
		
		/*
		 * Make the mailBody object
		 * and get the primary text content of the message using getText method */
		MailBody mailBody = new MailBody(MailHelper.getText(chosenMessage));
		
		
		/* get the secret (session) key from mailBody object
		 * use getEncKeyBytes() method*/
		byte[] secretKeyByteArray = mailBody.getEncKeyBytes();
		
		//get encoded message from mailBody object
		String encMessage = mailBody.getEncMessage();
		
		//asymmetric algorithm is RSA
		SecretKey secretKey = new SecretKeySpec(secretKeyByteArray, "RSA");
		
		/*
		 * instantiate a KeyStoreReader class to get keystore
		 * and private key*/
		KeyStoreReader keyStoreReader = new KeyStoreReader();
		
		
		/*
		 * get key store*/
		KeyStore keyStore = keyStoreReader.readKeyStore("./data/UserB.jks", "54321".toCharArray());
		
		/*
		 * get the private key*/
		PrivateKey privateKey = keyStoreReader.getPrivateKeyFromKeyStore(keyStore, "userb", "54321".toCharArray());
		
	    
        //TODO: Decrypt a message and decompress it. The private key is stored in a file.
		Cipher rsaCipherDec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		
		rsaCipherDec.init(Cipher.DECRYPT_MODE, privateKey);
		
		byte[] decryptedTxt = rsaCipherDec.doFinal(secretKey.getEncoded());
		
		SecretKey secretKeyAES = new SecretKeySpec(decryptedTxt, "DESede");
	
		
		Cipher tripleDESdec = Cipher.getInstance("DESede/CBC/PKCS5Padding");
		
		byte[] iv1 = mailBody.getIV1Bytes();
		IvParameterSpec ivParameterSpec1 = new IvParameterSpec(iv1);
		tripleDESdec.init(Cipher.DECRYPT_MODE, secretKeyAES, ivParameterSpec1);
		
		
		String receivedBodyTxt = new String(tripleDESdec.doFinal(Base64.decode(encMessage)));
		String decompressedBodyText = GzipUtil.decompress(Base64.decode(receivedBodyTxt));
		
		
		byte[] iv2 = mailBody.getIV2Bytes();
		IvParameterSpec ivParameterSpec2 = new IvParameterSpec(iv2);
		//inicijalizacija za dekriptovanje
		tripleDESdec.init(Cipher.DECRYPT_MODE, secretKeyAES, ivParameterSpec2);
		
		//dekompresovanje i dekriptovanje subject-a
		String decryptedSubjectTxt = new String(tripleDESdec.doFinal(Base64.decode(chosenMessage.getSubject())));
		String decompressedSubjectTxt = GzipUtil.decompress(Base64.decode(decryptedSubjectTxt));
		
		
		
		Document doc = DataUtil.loadDocument();
		
		X509Certificate cer = (X509Certificate) keyStoreReader.getCertificateFromKeyStore(keyStore, "usera");
		
		if(DataUtil.verifySiganture(doc, cer)) {
			
			System.out.println(".... verification is successful");
		}
		
		System.out.println("");
		System.out.println("<-----TEST CASE FOR CHANGED MESSAGE CONTENT-irregular signature------>");
		
		System.out.println("Changing message content....");
		
		doc.getElementsByTagName("subject").item(0).setTextContent("changed content");
		
		if(!DataUtil.verifySiganture(doc, cer)) {
			
			System.out.println("");
			System.out.println(".... verification is failed");
			System.out.println("");
		}
		
		System.out.println("Body text: " + decompressedBodyText);
		System.out.println("Subject text: " + new String(decompressedSubjectTxt));
		
		
	}
}
