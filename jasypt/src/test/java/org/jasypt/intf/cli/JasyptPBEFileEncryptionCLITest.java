package org.jasypt.intf.cli;

import junit.framework.TestCase;

public class JasyptPBEFileEncryptionCLITest extends TestCase {
    
    public void testFileEncryption() {
        String[] cliArgs = {
                "inputFile=src/test/resources/testEncryption.yml",
                "password=Pass",
                "outputFile=src/test/resources/testEncryptionOutput.yml",
                "encryptedPrefix=ENC[[",
                "encryptedSuffix=]]",
                "decryptedPrefix=DEC[",
                "decryptedSuffix=]"};
        JasyptPBEFileEncryptionCLI.main(cliArgs);
    }
    
}
