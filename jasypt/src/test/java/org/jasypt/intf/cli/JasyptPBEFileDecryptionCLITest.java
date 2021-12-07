package org.jasypt.intf.cli;

import java.io.IOException;

import org.jasypt.commons.CommonUtils;

import junit.framework.TestCase;

public class JasyptPBEFileDecryptionCLITest extends TestCase {
	
	public void testFileDecryption() {
		
		// Test for yaml file
		System.out.println(System.getProperty("path.separator"));
        final String location = System.getProperty("user.dir") + "/";
        final String encryptedYamlFilePath = location + "src/test/resources/encryptedYamlFile.yml";
        final String decryptedYamlFilePath = location + "src/test/resources/decryptedYamlFile.yml";
        
        String encryptedStringForYamlFile = "Key1: Value1\nKey2: ENC[[hPsyq1qBSnn1BShmdAIE8A==]]\n"
                + "List1:\n  - ENC[[hPsyq1qBSnkHH2UdIzLuM75IKT6ZtgPe]]\n  - Element2\n"
                + "Map1:\n  MapKey1: ENC[[hPsyq1qBSnny4pSXZipEkA==]]\n  M"
                + "apKey2:\n    List:\n      Key1: Value1\n      Key2: ENC[[hPsyq1qBSnn1BShmdAIE8A==]]\n";
        
        String expectedDecryptedStringForYamlFile = "Key1: Value1\nKey2: DEC[sensitiveValue2]\n"
                + "List1:\n  - DEC[sensitiveElement1]\n  - Element2\n"
                + "Map1:\n  MapKey1: DEC[sensitiveValue1]\n  M"
                + "apKey2:\n    List:\n      Key1: Value1\n      Key2: DEC[sensitiveValue2]\n";
        
        // Create a encrypted yaml file
        try {
            CommonUtils.writeStringToFile(encryptedYamlFilePath, encryptedStringForYamlFile);
        } catch (IOException e) {
            fail("Couldn't create encryptedYamlFile.yml in src/test/resources");
        }
                
        // Decrypt the encrypted file
        String[] decryptionCliArgs = {
                "inputFile=src/test/resources/encryptedYamlFile.yml",
                "password=Pass",
                "outputFile=src/test/resources/decryptedYamlFile.yml",
                "encryptedPrefix=ENC[[",
                "encryptedSuffix=]]",
                "decryptedPrefix=DEC[",
                "decryptedSuffix=]",
                "saltGeneratorClassName=org.jasypt.salt.ZeroSaltGenerator",
                "ivGeneratorClassName=org.jasypt.iv.NoIvGenerator"};
        JasyptPBEFileDecryptionCLI.main(decryptionCliArgs);
        
        // Read the decrypted file
        String decryptedStringForYamlFile = null;
        try {
            decryptedStringForYamlFile = CommonUtils.getFileAsString(decryptedYamlFilePath);
        } catch (IOException e) {
            fail("Couldn't read src/test/resources/decryptedYamlFile.yml");
        }
        
        assertTrue("Decrypted file isn't same as original file.", expectedDecryptedStringForYamlFile.equals(decryptedStringForYamlFile));
        
        // Delete the files created for test
        CommonUtils.deleteFile(encryptedYamlFilePath);
        CommonUtils.deleteFile(decryptedYamlFilePath);
	}
}
