package model.keystore;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

//Class who is reading from key store file

public class KeyStoreReader {

	public KeyStore readKeyStore(String keyStoreFilePath, char[] password) {
		
		KeyStore keyStore = null;
		
		try {
			//the first parameter of this method is keystore type
			//the second one is provider
			keyStore = KeyStore.getInstance("JKS", "SUN");
			
			//the mthod load() is manditory
			BufferedInputStream in = new BufferedInputStream(new FileInputStream(keyStoreFilePath));
			keyStore.load(in, password);
			
		}catch(KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException | IOException e) {
		
			e.printStackTrace();
			
			System.err.println("Error has happened during KeyStore loading. You must check if the path is correct "
								+ "and if the password for opening keystore is correct");
			
		}
		
		return keyStore;	
			
	}
	
	//this method is reading certificate from keystore
	public Certificate getCertificateFromKeyStore(KeyStore keyStore, String alias) {
		
		Certificate certificate = null;
		
		try {
			
			certificate = keyStore.getCertificate(alias);
		}catch(KeyStoreException e) {
			
			e.printStackTrace();
		}
		
		if(certificate == null) {
			
			System.err.println("Keystore is null! Check if the alias is correct");
		}
		
		return certificate;
		
	}
	
	//this method returns PrivateKey from keystore
	public PrivateKey getPrivateKeyFromKeyStore(KeyStore kStore, String alias, char[] password) {
		
		PrivateKey privateKey = null;
		
		try {
			
			privateKey = (PrivateKey) kStore.getKey(alias, password);
			
		}catch(UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
			
				e.printStackTrace();
		}
		
		if(privateKey == null) {
			
			System.err.println("Private key is null. Please check if an alias and password are correct!");
		}
		
		return privateKey;
	}
	
	//this method returns PublicKey from certificate
	public PublicKey getPublicKeyFromKeyStore(Certificate certificate) {
		
		return certificate.getPublicKey();
	}
	
}
