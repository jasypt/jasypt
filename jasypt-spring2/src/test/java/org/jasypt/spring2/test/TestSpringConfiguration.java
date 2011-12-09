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
package org.jasypt.spring2.test;


import junit.framework.TestCase;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.spring2.configuration.ConfigurationProperties;
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
}
