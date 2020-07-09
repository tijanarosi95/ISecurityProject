package util;


import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class DataUtil {
	
	public static void generateXML(String recivier, String subject, String body) {
		
		try {
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.newDocument();
			
			Element rootElement = doc.createElement("root");
			doc.appendChild(rootElement);
			
			Element message = doc.createElement("message");
			doc.appendChild(message);
			
			Element messageRecipient = doc.createElement("recipient");
			messageRecipient.appendChild(doc.createTextNode(recivier));
			message.appendChild(messageRecipient);
			
			Element messageSubject = doc.createElement("subject");
			messageSubject.appendChild(doc.createTextNode(subject));
			message.appendChild(messageSubject);
			
			Element messageBody = doc.createElement("body");
			messageRecipient.appendChild(doc.createTextNode(body));
			message.appendChild(messageBody);
			
		}catch(Exception ex) {ex.printStackTrace();}
	}

}
