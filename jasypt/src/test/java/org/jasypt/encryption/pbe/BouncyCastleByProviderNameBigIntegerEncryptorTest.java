/*
 * =============================================================================
 * 
 *   Copyright (c) 2007, The JASYPT team (http://www.jasypt.org)
 * 
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 * 
 * =============================================================================
 */
package org.jasypt.encryption.pbe;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class BouncyCastleByProviderNameBigIntegerEncryptorTest 
        extends AbstractPBEBigIntegerEncryptorTest {

    protected void setUp() throws Exception {
        super.setUp();
        Security.addProvider(new BouncyCastleProvider());
    }
    
    protected PBEBigIntegerEncryptor createPBEIntegerEncryptor() {
        StandardPBEBigIntegerEncryptor encryptor = new StandardPBEBigIntegerEncryptor();
        encryptor.setAlgorithm("PBEWITHSHA256AND128BITAES-CBC-BC");
        encryptor.setProviderName("BC");
        return encryptor;
    }

}
