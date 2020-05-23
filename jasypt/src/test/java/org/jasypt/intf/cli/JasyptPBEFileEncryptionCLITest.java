package org.jasypt.intf.cli;

import junit.framework.TestCase;

import java.io.IOException;

import org.jasypt.commons.CommonUtils;

public class JasyptPBEFileEncryptionCLITest extends TestCase {
    
    
    public void testFileEncryptionDecryption() {
        
        // Test for yaml file
        final String location = System.getProperty("user.dir") + "/";
        final String plainYamlFilePath = location + "src/test/resources/plainYamlFile.yml";
        final String encryptedYamlFilePath = location + "src/test/resources/encryptedYamlFile.yml";
        final String decryptedYamlFilePath = location + "src/test/resources/decryptedYamlFile.yml";
        
        String plainStringForYamlFile = "Key1: Value1\nKey2: DEC[sensitiveValue2]\n"
                + "List1:\n  - DEC[sensitiveElement1]\n  - Element2\n"
                + "Map1:\n  MapKey1: DEC[sensitiveValue1]\n  M"
                + "apKey2:\n    List:\n      Key1: Value1\n      Key2: DEC[sensitiveValue2]\n";
        
        
        // Create a plain yaml file
        try {
            CommonUtils.writeStringToFile(plainYamlFilePath, plainStringForYamlFile);
        } catch (IOException e) {
            fail("Couldn't create plainYamlFile.yml in src/test/resources");
        }
        
        // Encrypt the plain file
        String[] encryptionCliArgs = {
                "inputFile=src/test/resources/plainYamlFile.yml",
                "password=Pass",
                "outputFile=src/test/resources/encryptedYamlFile.yml",
                "encryptedPrefix=ENC[[",
                "encryptedSuffix=]]",
                "decryptedPrefix=DEC[",
                "decryptedSuffix=]"};
        JasyptPBEFileEncryptionCLI.main(encryptionCliArgs);
        
        // Read the encrypted file
        String encryptedStringForYamlFile = null;
        try {
            encryptedStringForYamlFile = CommonUtils.getFileAsString(encryptedYamlFilePath);
        } catch (IOException e) {
            fail("Couldn't read src/test/resources/encryptedYamlFile.yml");
        }
        
        // Verify encryption was done
        assertFalse("Encrypted file is same as the decrypted file.", plainStringForYamlFile.equals(encryptedStringForYamlFile));
        
        
        // Decrypt the encrypted file
        String[] decryptionCliArgs = {
                "inputFile=src/test/resources/encryptedYamlFile.yml",
                "password=Pass",
                "outputFile=src/test/resources/decryptedYamlFile.yml",
                "encryptedPrefix=ENC[[",
                "encryptedSuffix=]]",
                "decryptedPrefix=DEC[",
                "decryptedSuffix=]"};
        JasyptPBEFileDecryptionCLI.main(decryptionCliArgs);
        
        // Read the decrypted file
        String decryptedStringForYamlFile = null;
        try {
            decryptedStringForYamlFile = CommonUtils.getFileAsString(decryptedYamlFilePath);
        } catch (IOException e) {
            fail("Couldn't read src/test/resources/decryptedYamlFile.yml");
        }
        
        // Verify decrypted file matches the original one
        assertTrue("Decrypted file isn't same as original file.", decryptedStringForYamlFile.equals(plainStringForYamlFile));
        
        // Delete the files created for test
        CommonUtils.deleteFile(plainYamlFilePath);
        CommonUtils.deleteFile(encryptedYamlFilePath);
        CommonUtils.deleteFile(decryptedYamlFilePath);
    }
    
}
