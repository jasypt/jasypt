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
package org.jasypt.spring3.test;


import junit.framework.TestCase;

import org.apache.commons.lang.ArrayUtils;
import org.jasypt.digest.StandardStringDigester;
import org.jasypt.digest.StringDigester;
import org.jasypt.encryption.ByteEncryptor;
import org.jasypt.encryption.StringEncryptor;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.spring3.configuration.ConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * 
 * @author Soraya S&aacute;nchez
 *
 */
public class TestSpringConfiguration extends TestCase {

    private final static String CONFIGURATION_ENCRYPTOR_BEAN_NAME = "configurationEncryptor";
    private final static String CONFIGURATION_PROPERTIES_BEAN_NAME = "configurationProperties";
    
    private final static String BYTE_ENCRYPTOR_BEAN_NAME = "be";
    private final static String STRING_ENCRYPTOR_BEAN_NAME = "se";
    private final static String STRING_DIGESTER_BEAN_NAME = "sd";
    
    private static ApplicationContext ctx;

    
    
	protected void setUp() throws Exception {
	    super.setUp();
	    initSpring();
        
    }

	public static void initSpring() {
	    ctx = new ClassPathXmlApplicationContext(new String[] {"spring.xml"});
	}
	
	
	
	public void testEncryptedProperties() throws Exception {
		    
	    ConfigurationProperties configurationProperties = 
	        (ConfigurationProperties) ctx.getBean(CONFIGURATION_PROPERTIES_BEAN_NAME);
	    StringEncryptor stringEncryptor = 
            (StringEncryptor) ctx.getBean(CONFIGURATION_ENCRYPTOR_BEAN_NAME);
	    	    
	    assertEquals(configurationProperties.getLocation(), 
	            configurationProperties.getLocatinPlainValue());
	   
	    assertEquals(stringEncryptor.decrypt(configurationProperties.getLocationEncryptedValue()),
	            configurationProperties.getLocation());
       
	}
	
	public void testNamespace() throws Exception {
	    
	    StandardPBEByteEncryptor standardPBEByteEncryptor = 
            new StandardPBEByteEncryptor();
	    standardPBEByteEncryptor.setPassword("jasypt");
	    standardPBEByteEncryptor.setAlgorithm("PBEWithMD5AndDES");
        
	    ByteEncryptor byteEncryptor = 
            (ByteEncryptor) ctx.getBean(BYTE_ENCRYPTOR_BEAN_NAME);
        assertTrue(ArrayUtils.isEquals(new byte[] {5, 7, 13}, 
                standardPBEByteEncryptor.decrypt(byteEncryptor.encrypt(new byte[] {5, 7, 13}))));
        
        
        
        
	    StandardPBEStringEncryptor standardPBEStringEncryptor = 
            new StandardPBEStringEncryptor();
        standardPBEStringEncryptor.setPassword("jasypt");
        standardPBEStringEncryptor.setAlgorithm("PBEWithMD5AndDES");
        standardPBEStringEncryptor.setStringOutputType("hexadecimal");
        
	    StringEncryptor stringEncryptor = 
            (StringEncryptor) ctx.getBean(STRING_ENCRYPTOR_BEAN_NAME);
        assertEquals("jasypt", 
                standardPBEStringEncryptor.decrypt(stringEncryptor.encrypt("jasypt")));
        
	    
        
        StandardStringDigester standardStringDigester = 
            new StandardStringDigester();
        standardStringDigester.setAlgorithm("SHA-1");
        standardStringDigester.setStringOutputType("hexa");
        
        StringDigester stringDigester = 
            (StringDigester) ctx.getBean(STRING_DIGESTER_BEAN_NAME);
        assertTrue(stringDigester.matches("jasypt", 
                standardStringDigester.digest("jasypt")));
        assertTrue(standardStringDigester.matches("jasypt", 
                stringDigester.digest("jasypt")));
        
	}
}
