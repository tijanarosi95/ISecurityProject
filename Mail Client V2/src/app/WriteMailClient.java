package app;


import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;

import com.google.api.services.gmail.Gmail;

import model.keystore.KeyStoreReader;
import model.mailclient.MailBody;
import util.Base64;
import util.GzipUtil;
import util.IVHelper;
import support.MailHelper;
import support.MailWritter;

public class WriteMailClient extends MailClient {

	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	
	public static void main(String[] args) {
		
        try {
        	Gmail service = getGmailService();
            
        	System.out.println("Insert a reciever:");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String reciever = reader.readLine();
        	
            System.out.println("Insert a subject:");
            String subject = reader.readLine();
            
            
            System.out.println("Insert body:");
            String body = reader.readLine();
            
            
            //Compression
            String compressedSubject = Base64.encodeToString(GzipUtil.compress(subject));
            String compressedBody = Base64.encodeToString(GzipUtil.compress(body));
            
            //Key generation
            KeyGenerator keyGen = KeyGenerator.getInstance("DESede"); 
			SecretKey secretKey = keyGen.generateKey();
			Cipher desCipherEnc = Cipher.getInstance("DESede/CBC/PKCS5Padding");
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec1 = IVHelper.createIV();
			desCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec1);
			
			
			//sifrovanje
			byte[] ciphertext = desCipherEnc.doFinal(compressedBody.getBytes());
			String ciphertextStr = Base64.encodeToString(ciphertext);
			System.out.println("Kriptovan tekst: " + ciphertextStr);
			
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec2 = IVHelper.createIV();
			desCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);
			
			byte[] ciphersubject = desCipherEnc.doFinal(compressedSubject.getBytes());
			String ciphersubjectStr = Base64.encodeToString(ciphersubject);
			System.out.println("Kriptovan subject: " + ciphersubjectStr);
			
			KeyStoreReader keyStoreReader = new KeyStoreReader();
			
			KeyStore keyStoreA = keyStoreReader.readKeyStore("./data/UserA.jks", "12345".toCharArray());
			KeyStore keyStoreB = keyStoreReader.readKeyStore("./data/UserB.jks", "54321".toCharArray());
			
			
			PrivateKey privateKey = keyStoreReader.getPrivateKeyFromKeyStore(keyStoreA, "usera", "12345".toCharArray());
			
			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initSign(privateKey);
			
			//MimeMessage does not implement Serializable interface FIX THAT--->Transform message to XML
			byte[] messageBytes = objectToByteArray(MailHelper.createMimeMessage(reciever, ciphersubjectStr, ciphertextStr));
			signature.update(messageBytes);
			
			byte[] digitalSign = signature.sign();
			
			Certificate userBCer = keyStoreReader.getCertificateFromKeyStore(keyStoreB, "userb");
			PublicKey publicKeyUserB = keyStoreReader.getPublicKeyFromKeyStore(userBCer);
			
			/*
			 * To instantiate a Cipher object, I must call static method getInstance
			 * passing the name of requested transformation
			 * In this case we instantiate the Cipher object as RSA cipher with
			 * ECB mode of operation and PKCS1Padding scheme*/
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			
			cipher.init(Cipher.ENCRYPT_MODE, publicKeyUserB);
			
			/*
			 * after initializing the cipher object, call doFinal method to
			 * perform encryption operation who return a byte array 
			 * */
			byte[] encriptedKey = cipher.doFinal(secretKey.getEncoded());
			
			/*
			 * Encripted secret key transmit through MailBody constructor with Iv */
			MailBody mailBody = new MailBody(ciphertext, ivParameterSpec1.getIV(), ivParameterSpec2.getIV(), encriptedKey, digitalSign);
			
			
			String mailToCSV = mailBody.toCSV();
			
			//snimaju se bajtovi kljuca i IV.
			JavaUtils.writeBytesToFilename(KEY_FILE, secretKey.getEncoded());
			JavaUtils.writeBytesToFilename(IV1_FILE, ivParameterSpec1.getIV());
			JavaUtils.writeBytesToFilename(IV2_FILE, ivParameterSpec2.getIV());
			
        	MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr, mailToCSV);
        	MailWritter.sendMessage(service, "me", mimeMessage);
        	
        }catch (Exception e) {
        	e.printStackTrace();
		}
	}
	
	private static byte[] objectToByteArray(MimeMessage message) {
		
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream out = null;
		try {
		  out = new ObjectOutputStream(bos);   
		  out.writeObject(message);
		  out.flush();
		  byte[] messageBytes = bos.toByteArray();

		 return messageBytes;
		 
		}catch(Exception ex) {ex.printStackTrace();
		
		} finally {
		  try {
		    bos.close();
		  } catch (IOException ex) {
			  ex.printStackTrace();
		  }
		}
		return null;	
	}
}
