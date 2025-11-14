package org.jasypt.intf.service;

import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;

import junit.framework.TestCase;

public class FileEncryptorServiceTest extends TestCase {
	
	public void testEncrypt() {
		
		String plainStringForYamlFile = "Key1: Value1\nKey2: DEC[sensitiveValue2]\n"
                + "List1:\n  - DEC[sensitiveElement1]\n  - Element2\n"
                + "Map1:\n  MapKey1: DEC[sensitiveValue1]\n  M"
                + "apKey2:\n    List:\n      Key1: Value1\n      Key2: DEC[sensitiveValue2]\n";
		
		String expectedEncryptedStringForYamlFile = "Key1: Value1\nKey2: ENC[[hPsyq1qBSnn1BShmdAIE8A==]]\n"
                + "List1:\n  - ENC[[hPsyq1qBSnkHH2UdIzLuM75IKT6ZtgPe]]\n  - Element2\n"
                + "Map1:\n  MapKey1: ENC[[hPsyq1qBSnny4pSXZipEkA==]]\n  M"
                + "apKey2:\n    List:\n      Key1: Value1\n      Key2: ENC[[hPsyq1qBSnn1BShmdAIE8A==]]\n";
		
		String password = "Pass";
		String encryptedPrefix = "ENC[[";
        String encryptedSuffix = "]]";
        String decryptedPrefix = "DEC[";
        String decryptedSuffix = "]";
        
        SimpleStringPBEConfig config = new SimpleStringPBEConfig();
        config.setPassword(password);
        config.setSaltGeneratorClassName("org.jasypt.salt.ZeroSaltGenerator");
        config.setIvGeneratorClassName("org.jasypt.iv.NoIvGenerator");
        
        FileEncryptorService fileEncryptorService = new FileEncryptorService();
        String encryptedStringForYamlFile = fileEncryptorService.encrypt(
        		plainStringForYamlFile,
        		config,
        		encryptedPrefix,
        		encryptedSuffix,
        		decryptedPrefix,
        		decryptedSuffix,
        		false);
                
        assertTrue("Encrypted file isn't same as expected.", expectedEncryptedStringForYamlFile.equals(encryptedStringForYamlFile));
        
	}
	
	public void testDecrypt() {
		
		String encryptedStringForYamlFile = "Key1: Value1\nKey2: ENC[[hPsyq1qBSnn1BShmdAIE8A==]]\n"
                + "List1:\n  - ENC[[hPsyq1qBSnkHH2UdIzLuM75IKT6ZtgPe]]\n  - Element2\n"
                + "Map1:\n  MapKey1: ENC[[hPsyq1qBSnny4pSXZipEkA==]]\n  M"
                + "apKey2:\n    List:\n      Key1: Value1\n      Key2: ENC[[hPsyq1qBSnn1BShmdAIE8A==]]\n";
		
		String expectedDecryptedStringForYamlFile = "Key1: Value1\nKey2: DEC[sensitiveValue2]\n"
                + "List1:\n  - DEC[sensitiveElement1]\n  - Element2\n"
                + "Map1:\n  MapKey1: DEC[sensitiveValue1]\n  M"
                + "apKey2:\n    List:\n      Key1: Value1\n      Key2: DEC[sensitiveValue2]\n";
		
		String password = "Pass";
		String encryptedPrefix = "ENC[[";
        String encryptedSuffix = "]]";
        String decryptedPrefix = "DEC[";
        String decryptedSuffix = "]";
        
        SimpleStringPBEConfig config = new SimpleStringPBEConfig();
        config.setPassword(password);
        config.setSaltGeneratorClassName("org.jasypt.salt.ZeroSaltGenerator");
        config.setIvGeneratorClassName("org.jasypt.iv.NoIvGenerator");
        
        FileEncryptorService fileEncryptorService = new FileEncryptorService();
        String decryptedStringForYamlFile = fileEncryptorService.decrypt(
        		encryptedStringForYamlFile,
        		config,
        		encryptedPrefix,
        		encryptedSuffix,
        		decryptedPrefix,
        		decryptedSuffix,
        		false);
        
        assertTrue("Decrypted file isn't same as expected.", expectedDecryptedStringForYamlFile.equals(decryptedStringForYamlFile));
        
	}
	
}
