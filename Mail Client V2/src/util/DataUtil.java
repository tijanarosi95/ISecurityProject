package util;


import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import model.keystore.KeyStoreReader;

public class DataUtil {
	
	static {
	  	
	      Security.addProvider(new BouncyCastleProvider());
	      org.apache.xml.security.Init.init();
	  }
	
	public static void generateXML(String recivier, String subject, String body) {
		
		try {
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.newDocument();
			
			Element rootElement = doc.createElement("root");
			doc.appendChild(rootElement);
			
			Element message = doc.createElement("message");
			rootElement.appendChild(message);
			
			Element messageRecipient = doc.createElement("recipient");
			messageRecipient.appendChild(doc.createTextNode(recivier));
			message.appendChild(messageRecipient);
			
			Element messageSubject = doc.createElement("subject");
			messageSubject.appendChild(doc.createTextNode(subject));
			message.appendChild(messageSubject);
			
			Element messageBody = doc.createElement("body");
			messageBody.appendChild(doc.createTextNode(body));
			message.appendChild(messageBody);
			
			KeyStoreReader keyStoreReader = new KeyStoreReader();
			
			KeyStore keyStoreA = keyStoreReader.readKeyStore("./data/UserA.jks", "12345".toCharArray());
			
			PrivateKey privateKeyA = keyStoreReader.getPrivateKeyFromKeyStore(keyStoreA, "usera", "12345".toCharArray());
			
			Certificate userAcer = keyStoreReader.getCertificateFromKeyStore(keyStoreA, "usera");
			
			//create Signature object
			XMLSignature sig = new XMLSignature(doc,  null, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
			
			//create a transformations on document
			Transforms transforms = new Transforms(doc);
		
			//enveloped type
			transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
			//normalization
			transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS);
			
			//whole document was signed
			sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
			
			//in keyinfo we set publickey and cer
			sig.addKeyInfo(userAcer.getPublicKey());
			sig.addKeyInfo((X509Certificate) userAcer);
			
			rootElement.appendChild(sig.getElement());
			
			sig.sign(privateKeyA);	
			System.out.println("....... signed");
			
			//save signature into messages.xml in data directory
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(new File("./data/message.xml"));
			transformer.transform(source, result);
			
			
			
		}catch(Exception ex) {ex.printStackTrace();}
	}
	
	public static Document loadDocument() {
		
		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document document = db.parse(new File("./data/message.xml"));

			return document;
		} catch (FactoryConfigurationError e) {
			e.printStackTrace();
			return null;
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
			return null;
		} catch (SAXException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
		
	}
	
	public static boolean verifySiganture(Document doc, X509Certificate cer) {
		
		try {
			
			NodeList nodes = doc.getElementsByTagName("ds:Signature");
			
			if (nodes == null || nodes.getLength() == 0) {
				throw new Exception("Can't find signature in document.");
			}
			
			DOMValidateContext ctx = new DOMValidateContext(cer.getPublicKey(), nodes.item(0));
			XMLSignatureFactory sigF = XMLSignatureFactory.getInstance("DOM");
			javax.xml.crypto.dsig.XMLSignature xmlSignature = sigF.unmarshalXMLSignature(ctx);
			
			return xmlSignature.validate(ctx);
			
		}catch(Exception ex) {
			
			ex.printStackTrace();
			return false;
		}
	}

}
