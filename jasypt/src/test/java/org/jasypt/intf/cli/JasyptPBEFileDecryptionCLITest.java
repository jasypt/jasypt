package org.jasypt.intf.cli;

import junit.framework.TestCase;

public class JasyptPBEFileDecryptionCLITest extends TestCase {
    
    public void testFileDecryption() {
        String[] cliArgs = {
                "inputFile=src/test/resources/testDecryption.yml",
                "password=Pass",
                "outputFile=src/test/resources/testDecryptionOutput.yml",
                "encryptedPrefix=ENC[[",
                "encryptedSuffix=]]",
                "decryptedPrefix=DEC[",
                "decryptedSuffix=]"};
        JasyptPBEFileDecryptionCLI.main(cliArgs);
    }
}
