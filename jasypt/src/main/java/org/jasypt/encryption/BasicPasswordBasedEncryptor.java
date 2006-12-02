package org.jasypt.encryption;

import javax.crypto.Cipher;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.Validate;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.naming.ParameterNaming;
import org.jasypt.util.ParameterUtils;

// TODO: Add name for it to be configurable
// TODO: Get password from env or system props
public class BasicPasswordBasedEncryptor implements EncryptorAndDecryptor {

    public static final boolean DEFAULT_BASE64_ENCODED = true;
    public static final String DEFAULT_DIGEST_ALGORITHM = "MD5";
    public static final String DEFAULT_ENCRYPTION_ALGORITHM = "DES";
    
    private static final String CIPHER_ALGORITHM_PATTERN =
        "PBEWith<digest>And<encryption>";

    private static final byte[] PBE_SALT = 
        {
            (byte)0x4d,(byte)0x4f,(byte)0x52,(byte)0x45,
            (byte)0x53,(byte)0x4f,(byte)0x44,(byte)0x41
        };

    private static final int PBE_ITERARION_COUNT = 10;

    private static PBEParameterSpec PBE_PARAMETER_SPEC = 
        new PBEParameterSpec(PBE_SALT, PBE_ITERARION_COUNT);
    
    private boolean initialized = false;
    
    private String digestAlgorithm = DEFAULT_DIGEST_ALGORITHM;
    private String encryptionAlgorithm = DEFAULT_ENCRYPTION_ALGORITHM;
    private String password = null;
    private boolean base64Encoded = DEFAULT_BASE64_ENCODED;

    private Cipher encryptCipher = null;
    private Cipher decryptCipher = null;
    private Base64 base64 = new Base64();

    
    private static String defaultPassword = null;


    
    static {

        defaultPassword =
            ParameterUtils.getParameterizedValue(
                    ParameterNaming.PBE_PASSWORD_SYSTEM_PROPERTY,
                    ParameterNaming.PBE_PASSWORD_ENV_VARIABLE);
        if (defaultPassword == null) {
            defaultPassword = DEFAULT_PASSWORD;
        }
        
    }

    
    
    public BasicPasswordBasedEncryptor() {
        this.password = defaultPassword;
    }
    
    
    public synchronized void setBase64Encoded(boolean base64Encoded) {
        if (this.base64Encoded != base64Encoded) {
            this.base64Encoded = base64Encoded;
            initialized = false;
        }
    }

    public synchronized void setDigestAlgorithm(String digestAlgorithm) {
        Validate.notEmpty(digestAlgorithm);
        if (!this.digestAlgorithm.equals(digestAlgorithm)) {
            this.digestAlgorithm = digestAlgorithm;
            initialized = false;
        }
    }

    public synchronized void setEncryptionAlgorithm(String encryptionAlgorithm) {
        Validate.notEmpty(encryptionAlgorithm);
        if (!this.encryptionAlgorithm.equals(encryptionAlgorithm)) {
            this.encryptionAlgorithm = encryptionAlgorithm;
            initialized = false;
        }
    }

    public synchronized void setPassword(String password) {
        Validate.notEmpty(password);
        if ((this.password == null) || (!this.password.equals(password))) {
            this.password = password;
            initialized = false;
        }
    }

    public boolean isBase64Encoded() {
        return base64Encoded;
    }

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public String getPassword() {
        return password;
    }

/*
    private synchronized void initialize() {
        
        if (!initialized) {
            
            if (password == null) {
                throw new InternalErrorException("Encryption password not set");
            }
                
            try {
                
                String algorithm = new String(CIPHER_ALGORITHM_PATTERN);
                algorithm = algorithm.replaceFirst("<digest>", digestAlgorithm);
                algorithm = algorithm.replaceFirst("<encryption>", encryptionAlgorithm);
                
                PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
                SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(algorithm);
                SecretKey key = factory.generateSecret(pbeKeySpec);
                
                encryptCipher = Cipher.getInstance(algorithm);
                encryptCipher.init(Cipher.ENCRYPT_MODE, key, PBE_PARAMETER_SPEC);
                decryptCipher = Cipher.getInstance(algorithm);
                decryptCipher.init(Cipher.DECRYPT_MODE, key, PBE_PARAMETER_SPEC);
                
            } catch (Exception e) {
                throw new InternalErrorException(e);
            }
            initialized = true;
        }
    }

    
    public static BasicPbeEncryptor getInitializedInstance(
            String password) {
        BasicPbeEncryptor encryptor = 
            new BasicPbeEncryptor();
        encryptor.setPassword(password);
        encryptor.initialize();
        return encryptor;
    }
    
    public static BasicPbeEncryptor getInitializedInstance(
            String password, boolean base64Encoded) {
        BasicPbeEncryptor encryptor = 
            new BasicPbeEncryptor();
        encryptor.setPassword(password);
        encryptor.setBase64Encoded(base64Encoded);
        encryptor.initialize();
        return encryptor;
    }
    
    public static BasicPbeEncryptor getInitializedInstance(
            String password, String digestAlgorithm, 
            String encryptionAlgorithm, boolean base64Encoded) {
        BasicPbeEncryptor encryptor = 
            new BasicPbeEncryptor();
        encryptor.setPassword(password);
        encryptor.setDigestAlgorithm(digestAlgorithm);
        encryptor.setEncryptionAlgorithm(encryptionAlgorithm);
        encryptor.setBase64Encoded(base64Encoded);
        encryptor.initialize();
        return encryptor;
    }
    
*/    
    public synchronized String encrypt(String message) 
            throws EncryptionOperationNotPossibleException {
        return null;
/*        
        Validate.notNull(message);
        if (!initialized) {
            initialize();
        }

        // Add two random characters to make encryption stronger
        StringBuffer messageBuffer = new StringBuffer();
        messageBuffer.append((char) (Math.random()*256));
        messageBuffer.append(message);
        messageBuffer.append((char) (Math.random()*256));
    
        byte[] encryptedBytes = null;
        try {
            encryptedBytes = 
                encryptCipher.doFinal(messageBuffer.toString().getBytes());
        } catch (Exception e) {
            throw new EncryptionNotPossibleException();
        }
 
        if (base64Encoded) {
            return new String(base64.encode(encryptedBytes));
        } else {
            return new String(encryptedBytes);
        }
*/        
    }
/*
*/    
    public synchronized String decrypt(String encryptedMessage) 
            throws EncryptionOperationNotPossibleException {
        return null;
/*        
        Validate.notNull(encryptedMessage);
        if (!initialized) {
            initialize();
        }
    
        byte[] messageBytes = null;
        if (base64Encoded) {
            messageBytes = base64.decode(encryptedMessage.getBytes()); 
        } else {
            messageBytes = encryptedMessage.getBytes();
        }
    
        byte[] decryptedBytes = null;
        try {
            decryptedBytes = decryptCipher.doFinal(messageBytes);  
        } catch (Exception e) {
            throw new DecryptionNotPossibleException();
        }

        if (decryptedBytes.length < 2) {
            throw new DecryptionNotPossibleException();
        }
        String decryptedMessage = new String(decryptedBytes);
        return decryptedMessage.substring(1, decryptedMessage.length() - 1);
*/        
    }    

    
}

