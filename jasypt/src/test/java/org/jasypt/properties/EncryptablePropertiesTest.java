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
package org.jasypt.properties;

import java.util.Properties;

import org.jasypt.util.text.BasicTextEncryptor;

import junit.framework.Assert;
import junit.framework.TestCase;

public class EncryptablePropertiesTest extends TestCase {

    
    public void testEncryptableProperties() throws Exception {

        final BasicTextEncryptor encryptor = new BasicTextEncryptor();
        encryptor.setPassword("jasypt");
        final Properties props = new EncryptableProperties(encryptor);
        
        props.load(Thread.currentThread().getContextClassLoader().getResourceAsStream("props.properties"));
        
        final String value = "Spain";
        
        final String locationPlain1 = props.getProperty("location.plain");
        final String locationPlain2 = props.getProperty("location.plain", "defaultPlain");
        final String locationPlain3 = (String) props.get("location.plain");
        final String locationEnc1 = props.getProperty("location.enc");
        final String locationEnc2 = props.getProperty("location.enc", "defaultEnc");
        final String locationEnc3 = (String) props.get("location.enc");
        final String nonExisting1 = props.getProperty("non.existing");
        final String nonExisting2 = props.getProperty("non.existing", "defaultNon");
        final String nonExisting3 = (String) props.get("non.existing");
        
        Assert.assertEquals(value, locationPlain1);
        Assert.assertEquals(value, locationPlain2);
        Assert.assertEquals(value, locationPlain3);
        
        Assert.assertEquals(value, locationEnc1);
        Assert.assertEquals(value, locationEnc2);
        Assert.assertEquals(value, locationEnc3);
        
        Assert.assertNull(nonExisting1);
        Assert.assertEquals("defaultNon", nonExisting2);
        Assert.assertNull(nonExisting3);
        
    }
    
    
    
}
