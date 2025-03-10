package org.jasypt.hibernate6.encryptor;

import java.io.*;
import java.lang.reflect.Constructor;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.sql.Blob;
import java.util.Arrays;
import java.util.Properties;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.hibernate.engine.jdbc.BlobProxy;
import org.jasypt.commons.CommonUtils;
import org.jasypt.encryption.pbe.CleanablePasswordBased;
import org.jasypt.encryption.pbe.config.PBECleanablePasswordConfig;
import org.jasypt.encryption.pbe.config.PBEConfig;
import org.jasypt.exceptions.AlreadyInitializedException;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.hibernate6.converters.ConverterConfig;
import org.jasypt.hibernate6.converters.EncryptionParameters;
import org.jasypt.iv.IvGenerator;
import org.jasypt.iv.NoIvGenerator;
import org.jasypt.normalization.Normalizer;
import org.jasypt.salt.FixedSaltGenerator;
import org.jasypt.salt.RandomSaltGenerator;
import org.jasypt.salt.SaltGenerator;

public final class HibernatePBEInputStreamEncryptor implements CleanablePasswordBased {

    public static final String DEFAULT_ALGORITHM = "PBEWithMD5AndDES";
    public static final int DEFAULT_KEY_OBTENTION_ITERATIONS = 1000;
    public static final int DEFAULT_SALT_SIZE_BYTES = 8;
    public static final int DEFAULT_IV_SIZE_BYTES = 16;

    private String algorithm = "PBEWithMD5AndDES";
    private String providerName = null;
    private Provider provider = null;
    private char[] password = null;
    private int keyObtentionIterations = 1000;
    private SaltGenerator saltGenerator = null;
    private int saltSizeBytes = 8;
    private IvGenerator ivGenerator = null;
    private int ivSizeBytes = 16;
    private PBEConfig config = null;
    private boolean algorithmSet = false;
    private boolean passwordSet = false;
    private boolean iterationsSet = false;
    private boolean saltGeneratorSet = false;
    private boolean ivGeneratorSet = false;
    private boolean providerNameSet = false;
    private boolean providerSet = false;
    private boolean initialized = false;
    private SecretKey key = null;
    private Cipher encryptCipher = null;
    private Cipher decryptCipher = null;
    private boolean optimizingDueFixedSalt = false;
    private byte[] fixedSaltInUse = null;
    private String registeredName = null;

    private int blockSize = 1024;

    public HibernatePBEInputStreamEncryptor() {}

    public synchronized void setConfig(PBEConfig config) {
        CommonUtils.validateNotNull(config, "Config cannot be set null");
        if (this.isInitialized()) {
            throw new AlreadyInitializedException();
        } else {
            this.config = config;
        }
    }

    public synchronized void setAlgorithm(String algorithm) {
        CommonUtils.validateNotEmpty(algorithm, "Algorithm cannot be set empty");
        if (this.isInitialized()) {
            throw new AlreadyInitializedException();
        } else {
            this.algorithm = algorithm;
            this.algorithmSet = true;
        }
    }

    public synchronized void setPassword(String password) {
        CommonUtils.validateNotEmpty(password, "Password cannot be set empty");
        if (this.isInitialized()) {
            throw new AlreadyInitializedException();
        } else {
            if (this.password != null) {
                cleanPassword(this.password);
            }

            this.password = password.toCharArray();
            this.passwordSet = true;
        }
    }

    public synchronized void setPasswordCharArray(char[] password) {
        CommonUtils.validateNotNull(password, "Password cannot be set null");
        CommonUtils.validateIsTrue(password.length > 0, "Password cannot be set empty");
        if (this.isInitialized()) {
            throw new AlreadyInitializedException();
        } else {
            if (this.password != null) {
                cleanPassword(this.password);
            }

            this.password = new char[password.length];
            System.arraycopy(password, 0, this.password, 0, password.length);
            this.passwordSet = true;
        }
    }

    public synchronized void setKeyObtentionIterations(int keyObtentionIterations) {
        CommonUtils.validateIsTrue(keyObtentionIterations > 0, "Number of iterations for key obtention must be greater than zero");
        if (this.isInitialized()) {
            throw new AlreadyInitializedException();
        } else {
            this.keyObtentionIterations = keyObtentionIterations;
            this.iterationsSet = true;
        }
    }

    public synchronized void setSaltGenerator(SaltGenerator saltGenerator) {
        CommonUtils.validateNotNull(saltGenerator, "Salt generator cannot be set null");
        if (this.isInitialized()) {
            throw new AlreadyInitializedException();
        } else {
            this.saltGenerator = saltGenerator;
            this.saltGeneratorSet = true;
        }
    }

    public synchronized void setIvGenerator(IvGenerator ivGenerator) {
        if (this.isInitialized()) {
            throw new AlreadyInitializedException();
        } else {
            this.ivGenerator = ivGenerator;
            this.ivGeneratorSet = true;
        }
    }

    public synchronized void setProviderName(String providerName) {
        CommonUtils.validateNotNull(providerName, "Provider name cannot be set null");
        if (this.isInitialized()) {
            throw new AlreadyInitializedException();
        } else {
            this.providerName = providerName;
            this.providerNameSet = true;
        }
    }

    public synchronized void setProvider(Provider provider) {
        CommonUtils.validateNotNull(provider, "Provider cannot be set null");
        if (this.isInitialized()) {
            throw new AlreadyInitializedException();
        } else {
            this.provider = provider;
            this.providerSet = true;
        }
    }

    synchronized HibernatePBEInputStreamEncryptor[] cloneAndInitializeEncryptor(int size) {
        if (this.isInitialized()) {
            throw new EncryptionInitializationException("Cannot clone encryptor if it has been already initialized");
        } else {
            this.resolveConfigurationPassword();
            char[] copiedPassword = new char[this.password.length];
            System.arraycopy(this.password, 0, copiedPassword, 0, this.password.length);
            this.initialize();
            HibernatePBEInputStreamEncryptor[] clones = new HibernatePBEInputStreamEncryptor[size];
            clones[0] = this;

            for (int i = 1; i < size; ++i) {
                HibernatePBEInputStreamEncryptor clone = new HibernatePBEInputStreamEncryptor();
                clone.setPasswordCharArray(copiedPassword);
                if (CommonUtils.isNotEmpty(this.algorithm)) {
                    clone.setAlgorithm(this.algorithm);
                }

                clone.setKeyObtentionIterations(this.keyObtentionIterations);
                if (this.provider != null) {
                    clone.setProvider(this.provider);
                }

                if (this.providerName != null) {
                    clone.setProviderName(this.providerName);
                }

                if (this.saltGenerator != null) {
                    clone.setSaltGenerator(this.saltGenerator);
                }

                if (this.ivGenerator != null) {
                    clone.setIvGenerator(this.ivGenerator);
                }

                clones[i] = clone;
            }

            cleanPassword(copiedPassword);
            return clones;
        }
    }

    public boolean isInitialized() {
        return this.initialized;
    }

    public synchronized void initialize() {
        if (!this.initialized) {
            if (this.config != null) {
                this.resolveConfigurationPassword();
                String configAlgorithm = this.config.getAlgorithm();
                if (configAlgorithm != null) {
                    CommonUtils.validateNotEmpty(configAlgorithm, "Algorithm cannot be set empty");
                }

                Integer configKeyObtentionIterations = this.config.getKeyObtentionIterations();
                if (configKeyObtentionIterations != null) {
                    CommonUtils.validateIsTrue(configKeyObtentionIterations > 0, "Number of iterations for key obtention must be greater than zero");
                }

                SaltGenerator configSaltGenerator = this.config.getSaltGenerator();
                IvGenerator configIvGenerator = this.config.getIvGenerator();
                String configProviderName = this.config.getProviderName();
                if (configProviderName != null) {
                    CommonUtils.validateNotEmpty(configProviderName, "Provider name cannot be empty");
                }

                Provider configProvider = this.config.getProvider();
                this.algorithm = !this.algorithmSet && configAlgorithm != null ? configAlgorithm : this.algorithm;
                this.keyObtentionIterations = !this.iterationsSet && configKeyObtentionIterations != null ? configKeyObtentionIterations : this.keyObtentionIterations;
                this.saltGenerator = !this.saltGeneratorSet && configSaltGenerator != null ? configSaltGenerator : this.saltGenerator;
                this.ivGenerator = !this.ivGeneratorSet && configIvGenerator != null ? configIvGenerator : this.ivGenerator;
                this.providerName = !this.providerNameSet && configProviderName != null ? configProviderName : this.providerName;
                this.provider = !this.providerSet && configProvider != null ? configProvider : this.provider;
            }

            if (this.saltGenerator == null) {
                this.saltGenerator = new RandomSaltGenerator();
            }

            if (this.ivGenerator == null) {
                this.ivGenerator = new NoIvGenerator();
            }

            try {
                if (this.password == null) {
                    throw new EncryptionInitializationException("Password not set for Password Based Encryptor");
                }

                char[] normalizedPassword = Normalizer.normalizeToNfc(this.password);
                PBEKeySpec pbeKeySpec = new PBEKeySpec(normalizedPassword);
                cleanPassword(this.password);
                cleanPassword(normalizedPassword);
                if (this.provider != null) {
                    SecretKeyFactory factory = SecretKeyFactory.getInstance(this.algorithm, this.provider);
                    this.key = factory.generateSecret(pbeKeySpec);
                    this.encryptCipher = Cipher.getInstance(this.algorithm, this.provider);
                    this.decryptCipher = Cipher.getInstance(this.algorithm, this.provider);
                } else if (this.providerName != null) {
                    SecretKeyFactory factory = SecretKeyFactory.getInstance(this.algorithm, this.providerName);
                    this.key = factory.generateSecret(pbeKeySpec);
                    this.encryptCipher = Cipher.getInstance(this.algorithm, this.providerName);
                    this.decryptCipher = Cipher.getInstance(this.algorithm, this.providerName);
                } else {
                    SecretKeyFactory factory = SecretKeyFactory.getInstance(this.algorithm);
                    this.key = factory.generateSecret(pbeKeySpec);
                    this.encryptCipher = Cipher.getInstance(this.algorithm);
                    this.decryptCipher = Cipher.getInstance(this.algorithm);
                }
            } catch (EncryptionInitializationException e) {
                throw e;
            } catch (Throwable t) {
                throw new EncryptionInitializationException(t);
            }

            int algorithmBlockSize = this.encryptCipher.getBlockSize();
            if (algorithmBlockSize > 0) {
                this.saltSizeBytes = algorithmBlockSize;
                this.ivSizeBytes = algorithmBlockSize;
            }

            this.optimizingDueFixedSalt = this.saltGenerator instanceof FixedSaltGenerator && this.ivGenerator instanceof NoIvGenerator;
            if (this.optimizingDueFixedSalt) {
                this.fixedSaltInUse = this.saltGenerator.generateSalt(this.saltSizeBytes);
                PBEParameterSpec parameterSpec = new PBEParameterSpec(this.fixedSaltInUse, this.keyObtentionIterations);

                try {
                    this.encryptCipher.init(1, this.key, parameterSpec);
                    this.decryptCipher.init(2, this.key, parameterSpec);
                } catch (Exception var7) {
                    throw new EncryptionOperationNotPossibleException();
                }
            }

            this.initialized = true;
        }

    }

    private synchronized void resolveConfigurationPassword() {
        if (!this.initialized && this.config != null && !this.passwordSet) {
            char[] configPassword = null;
            if (this.config instanceof PBECleanablePasswordConfig) {
                configPassword = ((PBECleanablePasswordConfig) this.config).getPasswordCharArray();
            } else {
                String configPwd = this.config.getPassword();
                if (configPwd != null) {
                    configPassword = configPwd.toCharArray();
                }
            }

            if (configPassword != null) {
                CommonUtils.validateIsTrue(configPassword.length > 0, "Password cannot be set empty");
            }

            if (configPassword != null) {
                this.password = new char[configPassword.length];
                System.arraycopy(configPassword, 0, this.password, 0, configPassword.length);
                this.passwordSet = true;
                cleanPassword(configPassword);
            }

            if (this.config instanceof PBECleanablePasswordConfig) {
                ((PBECleanablePasswordConfig) this.config).cleanPassword();
            }
        }

    }

    private static void cleanPassword(char[] password) {
        if (password != null) {
            synchronized (password) {
                int pwdLength = password.length;

                for (int i = 0; i < pwdLength; ++i) {
                    password[i] = 0;
                }
            }
        }

    }

    private Blob toBlob(InputStream inputStream, long size) {
        return BlobProxy.generateProxy(inputStream, size);
    }

    private Blob doEncrypt(InputStream inputStream, byte[] iv, byte[] salt)
            throws Exception {

        int size = 0;
        File outputFile = File.createTempFile("encrypted_", "tmp");
        outputFile.deleteOnExit();

        try (FileOutputStream fileOut = new FileOutputStream(outputFile);
             CipherOutputStream cipherOut = new CipherOutputStream(fileOut, encryptCipher)) {

            // Write IV
            if (iv != null) {
                synchronized (ivGenerator) {
                    if (this.ivGenerator.includePlainIvInEncryptionResults()) {
                        fileOut.write(iv);
                    }
                }
                ivSizeBytes = iv.length;
            } else ivSizeBytes = 0;

            if (salt != null) {
                // Write Salt
                synchronized (saltGenerator) {
                    if (this.saltGenerator.includePlainSaltInEncryptionResults()) {
                        fileOut.write(salt);
                    }
                }
                saltSizeBytes = salt.length;
            } else saltSizeBytes = 0;

            // Encrypt directly while writing to file
            byte[] buffer = new byte[blockSize];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                cipherOut.write(buffer, 0, bytesRead);
            }

            cipherOut.flush();
        } catch (IOException e) {
            throw new EncryptionOperationNotPossibleException(e);
        }

        return toBlob(Files.newInputStream(outputFile.toPath()), outputFile.length());
    }

    public Blob encrypt(InputStream inputStream)
            throws EncryptionOperationNotPossibleException {
        if (inputStream == null) {
            return null;
        } else {
            if (!this.initialized) {
                this.initialize();
            }

            try {
                final byte[] salt;
                byte[] iv = null;

                if (this.optimizingDueFixedSalt) {
                    salt = this.fixedSaltInUse;
                    synchronized (this.encryptCipher) {
                        return doEncrypt(inputStream, iv, salt);
                    }
                } else {
                    salt = this.saltGenerator.generateSalt(this.saltSizeBytes);
                    iv = this.ivGenerator.generateIv(this.ivSizeBytes);
                    PBEParameterSpec parameterSpec = this.buildPBEParameterSpec(salt, iv);
                    synchronized (this.encryptCipher) {
                        this.encryptCipher.init(1, this.key, parameterSpec);
                        return doEncrypt(inputStream, iv, salt);
                    }
                }
            } catch (InvalidKeyException e) {
                this.handleInvalidKeyException(e);
                throw new EncryptionOperationNotPossibleException();
            } catch (Exception e) {
                throw new EncryptionOperationNotPossibleException(e);
            }
        }
    }

    public InputStream decrypt(InputStream encryptedStream) throws IOException {
        if (encryptedStream == null) {
            return null;
        }
        if (!this.isInitialized()) {
            this.initialize();
        }

        try {
            byte[] salt = null;
            if (this.saltGenerator.includePlainSaltInEncryptionResults()) {
                salt = new byte[this.saltSizeBytes];

                int bytesRead = 0;
                while (bytesRead < salt.length) {
                    int read = encryptedStream.read(salt, bytesRead, salt.length - bytesRead);
                    if (read == -1) {
                        throw new EncryptionOperationNotPossibleException("Unexpected EOF while reading salt");
                    }
                    bytesRead += read;
                }
            } else if (this.optimizingDueFixedSalt) {
                salt = this.fixedSaltInUse;
            } else {
                throw new EncryptionOperationNotPossibleException("Missing salt in encrypted file");
            }

            byte[] iv = null;
            if (this.ivGenerator.includePlainIvInEncryptionResults()) {
                iv = new byte[this.ivSizeBytes];

                int bytesRead = 0;
                while (bytesRead < iv.length) {
                    int read = encryptedStream.read(iv, bytesRead, iv.length - bytesRead);
                    if (read == -1) {
                        throw new EncryptionOperationNotPossibleException("Unexpected EOF while reading salt");
                    }
                    bytesRead += read;
                }
            } else {
                iv = this.ivGenerator.generateIv(this.ivSizeBytes);
            }

            // Initialize cipher
            if (!this.optimizingDueFixedSalt) {
                PBEParameterSpec parameterSpec = this.buildPBEParameterSpec(salt, iv);
                synchronized (this.decryptCipher) {
                    this.decryptCipher.init(Cipher.DECRYPT_MODE, this.key, parameterSpec);
                }
            }

            // Return a CipherInputStream that decrypts data as it's read
            return new CipherInputStream(encryptedStream, decryptCipher);

        } catch (IOException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new EncryptionOperationNotPossibleException(e);
        }
    }

    private PBEParameterSpec buildPBEParameterSpec(byte[] salt, byte[] iv) {
        PBEParameterSpec parameterSpec;
        try {
            Class[] parameters = new Class[]{byte[].class, Integer.TYPE, AlgorithmParameterSpec.class};
            Constructor<PBEParameterSpec> java8Constructor = PBEParameterSpec.class.getConstructor(parameters);
            Object[] parameterValues = new Object[]{salt, this.keyObtentionIterations, new IvParameterSpec(iv)};
            parameterSpec = java8Constructor.newInstance(parameterValues);
        } catch (Exception var7) {
            parameterSpec = new PBEParameterSpec(salt, this.keyObtentionIterations);
        }

        return parameterSpec;
    }

    private void handleInvalidKeyException(InvalidKeyException e) {
        if (e.getMessage() != null && e.getMessage().toUpperCase().indexOf("KEY SIZE") != -1) {
            throw new EncryptionOperationNotPossibleException("Encryption raised an exception. A possible cause is you are using strong encryption algorithms and you have not installed the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files in this Java Virtual Machine");
        }
    }

    public ConverterConfig generateConverterConfig() {
        Properties configProps = new Properties();
        if (this.registeredName != null) {
            configProps.setProperty(EncryptionParameters.ENCRYPTOR_NAME, this.registeredName);
        } else {
            configProps.setProperty(EncryptionParameters.KEY_OBTENTION_ITERATIONS, String.valueOf(keyObtentionIterations));
            configProps.setProperty(EncryptionParameters.ALGORITHM, algorithm);
            configProps.setProperty(EncryptionParameters.PASSWORD, String.valueOf(password));
        }

        return new ConverterConfig(configProps);
    }

    /**
     * Sets the registered name of the encryptor and adds it to the registry.
     *
     * @param registeredName the name with which the encryptor will be
     *                       registered.
     */
    public void setRegisteredName(final String registeredName) {
        if (this.registeredName != null) {
            // It had another name before, we have to clean
            HibernatePBEEncryptorRegistry.getInstance().
                    unregisterHibernatePBEByteEncryptor(this.registeredName);
        }
        this.registeredName = registeredName;
        HibernatePBEEncryptorRegistry.getInstance().
                registerHibernatePBEInputStreamEncryptor(this);
    }

    public String getRegisteredName() {
        return registeredName;
    }

    public int getIvSizeBytes() {
        return ivSizeBytes;
    }

    public int getSaltSizeBytes() {
        return saltSizeBytes;
    }

    public void setBlockSize(int blockSize) {
        this.blockSize = blockSize;
    }

    public int getBlockSize() {
        return blockSize;
    }
}
