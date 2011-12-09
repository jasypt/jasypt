/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2010, The JASYPT team (http://www.jasypt.org)
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
package org.jasypt.spring.properties;

import junit.framework.TestCase;


import java.util.HashMap;
import java.util.Map;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.util.text.TextEncryptor;


/*
 * ==Test resolveSystemProperty for encrypted env var==
 *
 * I don't have a great way to test the decryption of encrypted env var without requiring the test harness (surefire, IDE etc)
 * to have specified an encrypted environment variable.  Here are a few options
 * - reflection hack to change the underlying system env map -
 * http://stackoverflow.com/questions/318239/how-do-i-set-environment-variables-from-java. THis is what spring does to
 * test the propertyplaceholderconfigurer:
 *  https://src.springframework.org/svn/spring-framework/trunk/org.springframework.beans/src/test/java/org/springframework/beans/factory/config/PropertyPlaceholderConfigurerTests.java
 * - extract the call to super.resolveSystemProperty(key) in resolveSystemProperty to a protected method and the test
 * will use a testspecifc subclass (http://xunitpatterns.com/Test-Specific%20Subclass.html) that overrides that method.
 *
 * However, i really don't think it is that big of a deal.  The functionality responsible for getting system/env values
 * is defined in the super.  All this class does is check to see if they have the encryption delimiters.  I am pretty sure
 * I already went overboard on the test - ~100 lines of test for 3 lines of production code.
 *
 * User: carlos fernandez
 * Date: 6/28/11
 * Time: 10:38 PM
 */
public class EncryptablePropertyPlaceholderConfigurerTest extends TestCase {

    //duplicated prefix suffix values in PropertyValueEncryptionUtils because PVEU constants are private
    private static final String ENCRYPTED_VALUE_PREFIX = "ENC(";
    private static final String ENCRYPTED_VALUE_SUFFIX = ")";

    private String expectedDecryptedValue;
    private String encryptedValue;
    private String encryptedValueWithDelimiters;

    private String encryptedSysPropKey;
    private String unencryptedSysPropKey;
    private String unencryptedValue;

    public void setUp() {
        encryptedSysPropKey = "thisIsAnEncryptedSysPropertyKey";
        encryptedValue = "encryptedString";
        encryptedValueWithDelimiters = ENCRYPTED_VALUE_PREFIX + this.encryptedValue + ENCRYPTED_VALUE_SUFFIX;
        expectedDecryptedValue = "clearText";
        System.setProperty(encryptedSysPropKey, encryptedValueWithDelimiters);

        unencryptedSysPropKey = "thisIsAnUNEncryptedSysPropertyKey";
        unencryptedValue = "thisIsARegularString";
        System.setProperty(unencryptedSysPropKey, unencryptedValue);
    }

    public void testConvertPropertyValueNotEncrypted() {
        EncryptablePropertyPlaceholderConfigurer eppc = createPPCWithStringEncryptor();
        assertEquals(unencryptedValue, eppc.convertPropertyValue(unencryptedValue));
    }

    public void testConvertPropertyValueDecryptWithStringEncryptor() {
        EncryptablePropertyPlaceholderConfigurer eppc = createPPCWithStringEncryptor();
        assertEquals(expectedDecryptedValue, eppc.convertPropertyValue(encryptedValueWithDelimiters));
    }

    public void testConvertPropertyValueDecryptWithTextEncryptor() {
        EncryptablePropertyPlaceholderConfigurer eppc = createPPCWithTextEncryptor();
        assertEquals(expectedDecryptedValue, eppc.convertPropertyValue(encryptedValueWithDelimiters));
    }

    public void testResolveSystemPropertyNullSystemPropertyValue()
            throws Exception {
        EncryptablePropertyPlaceholderConfigurer ppc = createPPCWithTextEncryptor();
        assertNull(ppc.resolveSystemProperty("foofoofoo"));
    }

    public void testResolveSystemPropertyEncryptedSystemPropertyValue()
            throws Exception {
        EncryptablePropertyPlaceholderConfigurer ppc = createPPCWithTextEncryptor();
        assertEquals(expectedDecryptedValue, ppc.resolveSystemProperty(encryptedSysPropKey));
    }

    public void testResolveSystemPropertyUnencryptedSystemPropertyValue()
            throws Exception {
        EncryptablePropertyPlaceholderConfigurer ppc = createPPCWithStringEncryptor();
        assertEquals(unencryptedValue, ppc.resolveSystemProperty(unencryptedSysPropKey));
    }

    public void testResolveSystemPropertyUnencryptedEnvVar()
            throws Exception {
        //the expectation is that the system has the HOME env var
        String unencryptedEnvVarKey = "HOME";//this is expected to exist on windows and unix systems
        String unencryptedEnvVarValue = System.getenv(unencryptedEnvVarKey);
        //lets make sure the env variable is set & is not null
        assertNotNull("no home env variable found", unencryptedEnvVarValue);

        EncryptablePropertyPlaceholderConfigurer ppc = createPPCWithTextEncryptor();
        //allow ppc can check env vars
        ppc.setSearchSystemEnvironment(true);

        assertEquals(unencryptedEnvVarValue, ppc.resolveSystemProperty(unencryptedEnvVarKey));
    }

    private EncryptablePropertyPlaceholderConfigurer createPPCWithTextEncryptor() {
        StubTextEncryptor textEncryptor = new StubTextEncryptor();
        textEncryptor.addDecryption(encryptedValue, expectedDecryptedValue);
        return new EncryptablePropertyPlaceholderConfigurer(textEncryptor);
    }

    private EncryptablePropertyPlaceholderConfigurer createPPCWithStringEncryptor() {
        StubStringEncryptor stringEncryptor = new StubStringEncryptor();
        stringEncryptor.addDecryption(encryptedValue, expectedDecryptedValue);
        return new EncryptablePropertyPlaceholderConfigurer(stringEncryptor);
    }


    abstract class StubEncryptor {

        private Map decryptMap = new HashMap();

        public String decrypt(String encryptedMessage) {
            return (String)this.decryptMap.get(encryptedMessage);
        }

        public String encrypt(String message) {
            throw new UnsupportedOperationException();
        }

        public void addDecryption(String encrypted,
                String expectedDecryption) {
            this.decryptMap.put(encrypted, expectedDecryption);
        }

    }

    class StubStringEncryptor extends StubEncryptor implements StringEncryptor{}
    class StubTextEncryptor extends StubEncryptor implements TextEncryptor{}

}
