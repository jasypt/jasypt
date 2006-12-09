package org.jasypt.encryption;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ClassUtils;
import org.apache.commons.lang.Validate;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.naming.ParameterNaming;
import org.jasypt.util.ParameterUtils;

// TODO: Review algorithm: maybe remove the extra random chars?
// TODO: Review factory methods
// TODO: Create Unit tests
public class BasicPasswordBasedEncryptor implements EncryptorAndDecryptor {

    private static final Log log = 
        LogFactory.getLog(BasicPasswordBasedEncryptor.class);
    
    public static final boolean DEFAULT_BASE64_ENCODED = true;
    public static final String DEFAULT_DIGEST_ALGORITHM = "MD5";
    public static final String DEFAULT_ENCRYPTION_ALGORITHM = "DES";
    public static final String DEFAULT_NAME = 
        ClassUtils.getShortClassName(BasicPasswordBasedEncryptor.class);
    
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
    private boolean passwordInitialized = false;
    private boolean passwordSetFromDefault = false;
    
    private String digestAlgorithm = DEFAULT_DIGEST_ALGORITHM;
    private String encryptionAlgorithm = DEFAULT_ENCRYPTION_ALGORITHM;
    private String password = null;
    private boolean base64Encoded = DEFAULT_BASE64_ENCODED;
    
    private String name = DEFAULT_NAME;

    private Cipher encryptCipher = null;
    private Cipher decryptCipher = null;
    private Base64 base64 = new Base64();

    
    private static String defaultPassword = null;

    
    static {
        defaultPassword =
            ParameterUtils.getSystemProperty(
                    ParameterNaming.PBE_PASSWORD_SYSTEM_PROPERTY);
        if (defaultPassword != null) {
            log.info("[jasypt] Default password for basic password-" +
                    "based encryptors initialized from system property " +
                    "\'" + ParameterNaming.PBE_PASSWORD_SYSTEM_PROPERTY + "\'");
        } else {
            defaultPassword =
                ParameterUtils.getEnvVariable(
                        ParameterNaming.PBE_PASSWORD_ENV_VARIABLE);
            if (defaultPassword != null) {
                log.info("[jasypt] Default password for basic password-" +
                        "based encryptors initialized from environment " +
                        "variable \'" + 
                        ParameterNaming.PBE_PASSWORD_ENV_VARIABLE + "\'");
            }
        }
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
            passwordInitialized = false;
        }
        passwordSetFromDefault = false;
    }
    
    
    public synchronized void setName(String name) {
        Validate.notEmpty(name);
        if (!this.name.equals(name)) {
            this.name = name;
            initialized = false;
            if (passwordSetFromDefault) {
                passwordInitialized = false;
            }
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
    
    public String getName() {
        return name;
    }
    

    
    private synchronized void initializePassword() {
        
        if (password == null) {

            if (!DEFAULT_NAME.equals(name)) {
                    
                String systemPropertyName = 
                    ParameterNaming.PBE_PASSWORD_SYSTEM_PROPERTY_PREFIX +
                    name.toLowerCase() +
                    ParameterNaming.PBE_PASSWORD_SYSTEM_PROPERTY_SUFFIX;
                
                password =
                    ParameterUtils.getSystemProperty(systemPropertyName);
    
                if (password != null) {
                    log.info("[jasypt] Password for basic password-" +
                            "based encryptor with name \'" + name + "\' " +
                            "initialized from system property " +
                            "\'" + systemPropertyName + "\'");
                } else {
                
                    String envVariableName = 
                        ParameterNaming.PBE_PASSWORD_ENV_VARIABLE_PREFIX +
                        name.toUpperCase() +
                        ParameterNaming.PBE_PASSWORD_ENV_VARIABLE_SUFFIX;
                    
                    password =
                        ParameterUtils.getEnvVariable(envVariableName);
    
                    if (password != null) {
                        log.info("[jasypt] Password for basic password-" +
                                "based encryptor with name \'" + name + "\' " +
                                "initialized from environment variable \'" + 
                                envVariableName + "\'");
                    }
                    
                }
                
            }
            
            
            if (password == null) {
                if (defaultPassword != null) {
                    password = defaultPassword;
                } else {
                    throw new EncryptionInitializationException(
                            "Encryption password not set for " +
                            "basic password-based encryptor" +
                            ((DEFAULT_NAME.equals(name))?
                                "" : " with name \'" + name + "\'"));
                }
            }
            
            passwordSetFromDefault = true;
        }
        
        passwordInitialized = true;
        log.info("[jasypt] Password initialized for basic password-based " +
                "encryptor with name \'" + name + "\'");
        
    }
    
    
    private synchronized void initialize() {
        
        if (!initialized) {
        
            if (!passwordInitialized) {
                initializePassword();
            }
            
            try {
                
                String algorithm = new String(CIPHER_ALGORITHM_PATTERN);
                algorithm = 
                    algorithm.replaceFirst("<digest>", digestAlgorithm);
                algorithm = 
                    algorithm.replaceFirst("<encryption>", encryptionAlgorithm);
                
                PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
                SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(algorithm);
                SecretKey key = factory.generateSecret(pbeKeySpec);
                
                encryptCipher = Cipher.getInstance(algorithm);
                encryptCipher.init(
                        Cipher.ENCRYPT_MODE, key, PBE_PARAMETER_SPEC);
                decryptCipher = Cipher.getInstance(algorithm);
                decryptCipher.init(
                        Cipher.DECRYPT_MODE, key, PBE_PARAMETER_SPEC);
                
            } catch (Throwable t) {
                throw new EncryptionInitializationException(t);
            }
            initialized = true;
        }
    }

/*    
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
            throw new EncryptionOperationNotPossibleException();
        }
 
        if (base64Encoded) {
            return new String(base64.encode(encryptedBytes));
        } else {
            return new String(encryptedBytes);
        }
        
    }

    
    public synchronized String decrypt(String encryptedMessage) 
            throws EncryptionOperationNotPossibleException {
        
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
            throw new EncryptionOperationNotPossibleException();
        }

        if (decryptedBytes.length < 2) {
            throw new EncryptionOperationNotPossibleException();
        }
        String decryptedMessage = new String(decryptedBytes);
        return decryptedMessage.substring(1, decryptedMessage.length() - 1);
    }    

    
}

