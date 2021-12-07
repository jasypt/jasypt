package org.jasypt.intf.cli;

import junit.framework.TestCase;

import java.io.IOException;

import org.jasypt.commons.CommonUtils;

public class JasyptPBEFileEncryptionCLITest extends TestCase {
    
    
    public void testFileEncryption() {
        
        // Test for yaml file
        final String location = System.getProperty("user.dir") + "/";
        final String plainYamlFilePath = location + "src/test/resources/plainYamlFile.yml";
        final String encryptedYamlFilePath = location + "src/test/resources/encryptedYamlFile.yml";
        
        String plainStringForYamlFile = "Key1: Value1\nKey2: DEC[sensitiveValue2]\n"
                + "List1:\n  - DEC[sensitiveElement1]\n  - Element2\n"
                + "Map1:\n  MapKey1: DEC[sensitiveValue1]\n  M"
                + "apKey2:\n    List:\n      Key1: Value1\n      Key2: DEC[sensitiveValue2]\n";
        
        String expectedEncryptedStringForYamlFile = "Key1: Value1\nKey2: ENC[[hPsyq1qBSnn1BShmdAIE8A==]]\n"
                + "List1:\n  - ENC[[hPsyq1qBSnkHH2UdIzLuM75IKT6ZtgPe]]\n  - Element2\n"
                + "Map1:\n  MapKey1: ENC[[hPsyq1qBSnny4pSXZipEkA==]]\n  M"
                + "apKey2:\n    List:\n      Key1: Value1\n      Key2: ENC[[hPsyq1qBSnn1BShmdAIE8A==]]\n";
        
        // Create a plain yaml file
        try {
            CommonUtils.writeStringToFile(plainYamlFilePath, plainStringForYamlFile);
        } catch (IOException e) {
            fail("Couldn't create plainYamlFile.yml in src/test/resources");
        }
        
        // Encrypt the plain file using ZeroSaltGenerator and NoIvGenerator, so that we can know the expected output beforehand
        String[] encryptionCliArgs = {
                "inputFile=src/test/resources/plainYamlFile.yml",
                "password=Pass",
                "outputFile=src/test/resources/encryptedYamlFile.yml",
                "encryptedPrefix=ENC[[",
                "encryptedSuffix=]]",
                "decryptedPrefix=DEC[",
                "decryptedSuffix=]",
                "saltGeneratorClassName=org.jasypt.salt.ZeroSaltGenerator",
                "ivGeneratorClassName=org.jasypt.iv.NoIvGenerator"};
        JasyptPBEFileEncryptionCLI.main(encryptionCliArgs);
        
        // Read the encrypted file
        String encryptedStringForYamlFile = null;
        try {
            encryptedStringForYamlFile = CommonUtils.getFileAsString(encryptedYamlFilePath);
            System.out.println(encryptedStringForYamlFile);
        } catch (IOException e) {
            fail("Couldn't read src/test/resources/encryptedYamlFile.yml");
        }
        
        assertTrue("Encrypted file isn't same as expected.", encryptedStringForYamlFile.equals(expectedEncryptedStringForYamlFile));
        
        // Delete the files created for test
        CommonUtils.deleteFile(plainYamlFilePath);
        CommonUtils.deleteFile(encryptedYamlFilePath);
    }
    
}
