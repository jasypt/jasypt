package org.jasypt.properties;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.lang.Validate;
import org.jasypt.encryption.StringEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.util.text.TextEncryptor;

public class EncryptableProperties extends Properties {

    private static final long serialVersionUID = 6479795856725500639L;
    
    private final StringEncryptor stringEncryptor;
    private final TextEncryptor textEncryptor;
    
    private final Set encryptedPropertyNames;
    
    
    public EncryptableProperties(StringEncryptor stringEncryptor) {
        this(null, stringEncryptor);
    }
    
    
    public EncryptableProperties(TextEncryptor textEncryptor) {
        this(null, textEncryptor);
    }
    
    
    //TODO: Do something about the 1.5 and 1.6 methods. Implement and throw NotImplementedException?
    //      No problem with load operations, as they use "put", but... with store?
    
    public EncryptableProperties(Properties defaults, StringEncryptor stringEncryptor) {
        super(defaults);
        Validate.notNull(stringEncryptor, "Encryptor cannot be null");
        this.stringEncryptor = stringEncryptor;
        this.textEncryptor = null;
        this.encryptedPropertyNames = new HashSet();
    }


    
    public EncryptableProperties(Properties defaults, TextEncryptor textEncryptor) {
        super(defaults);
        Validate.notNull(textEncryptor, "Encryptor cannot be null");
        this.stringEncryptor = null;
        this.textEncryptor = textEncryptor;
        this.encryptedPropertyNames = new HashSet();
    }
    
    
    
    public void list(PrintStream out) {
        createUnencryptedEquivalent().list(out);
    }

    

    public void list(PrintWriter out) {
        createUnencryptedEquivalent().list(out);
    }


    /**
     * @deprecated
     */
    public synchronized void save(OutputStream out, String comments) {
        createUnencryptedEquivalent().save(out, comments);
    }

    

    public void store(OutputStream out, String comments) throws IOException {
        createUnencryptedEquivalent().store(out, comments);
    }


    
    public synchronized Object put(Object arg0, Object arg1) {
        return super.put(arg0, decode(arg0, arg1));
    }

    

    private synchronized Object decode(Object key, Object encodedValue) {
        if ((!(encodedValue instanceof String)) || 
                (!PropertyDecodingUtils.isEncryptedValue((String)encodedValue))) {
            return encodedValue;
        }
        this.encryptedPropertyNames.add(key);
        if (this.stringEncryptor != null) {
            return PropertyDecodingUtils.decode((String)encodedValue, this.stringEncryptor);
            
        }
        return PropertyDecodingUtils.decode((String)encodedValue, this.textEncryptor);
    }

    

    private synchronized Object encode(Object key, Object decodedValue) {
        if ((!(decodedValue instanceof String)) || 
                (!this.encryptedPropertyNames.contains(key))) {
            return decodedValue;
        }
        if (this.stringEncryptor != null) {
            return PropertyDecodingUtils.encode((String)decodedValue, this.stringEncryptor);
            
        }
        return PropertyDecodingUtils.encode((String)decodedValue, this.textEncryptor);
    }
    
    
    
    private Properties createUnencryptedEquivalent() {
        Properties auxProperties = new Properties();
        Iterator entriesIter = this.entrySet().iterator();
        while (entriesIter.hasNext()) {
            Map.Entry entry = (Map.Entry) entriesIter.next();
            auxProperties.put(entry.getKey(), encode(entry.getKey(), entry.getValue()));
        }
        return auxProperties;
    }


    
    
    public static void main(String[] args) throws Exception {
        
        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setPassword("daniel");

        Properties defProperties = new EncryptableProperties(encryptor);
        defProperties.setProperty("p3", "ENC(7y8QnPycD3ufR2hkEszGOw==)");
        
        
        EncryptableProperties properties = new EncryptableProperties(defProperties, encryptor);
//        properties.setProperty("p1", "HOLA");
//        properties.setProperty("p2", "ENC(7y8QnPycD3ufR2hkEszGOw==)");
        
        File fi = new File("C:/testing.properties");
        InputStream is = new FileInputStream(fi);
        properties.load(is);
        
        
        System.out.println(properties);
        System.out.println(properties.getProperty("p3"));

        properties.store(System.out, "My comments here..");
        
        
        File f = new File("C:/testing2.properties");
        if (f.createNewFile()) {
            System.out.println("Creating file...");
            OutputStream os = new FileOutputStream(f);
            properties.store(os, "Testing file");
        } else {
            System.out.println("Could not create file!");
        }
    }
    
    
}
