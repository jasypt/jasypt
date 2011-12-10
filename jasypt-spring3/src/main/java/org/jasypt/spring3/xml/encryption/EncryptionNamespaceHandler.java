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
package org.jasypt.spring3.xml.encryption;

import org.springframework.beans.factory.xml.NamespaceHandlerSupport;

/**
 * 
 * @since 1.9.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class EncryptionNamespaceHandler extends NamespaceHandlerSupport {

    
    public EncryptionNamespaceHandler() {
        super();
    }
    

    public void init() {
        
        registerBeanDefinitionParser("encryptor-config", new EncryptorConfigBeanDefinitionParser());       
        registerBeanDefinitionParser("byte-encryptor", 
                new EncryptorBeanDefinitionParser(EncryptorFactoryBean.ENCRYPTOR_TYPE_BYTE));       
        registerBeanDefinitionParser("string-encryptor", 
                new EncryptorBeanDefinitionParser(EncryptorFactoryBean.ENCRYPTOR_TYPE_STRING));       
        registerBeanDefinitionParser("big-decimal-encryptor", 
                new EncryptorBeanDefinitionParser(EncryptorFactoryBean.ENCRYPTOR_TYPE_BIG_DECIMAL));       
        registerBeanDefinitionParser("big-integer-encryptor", 
                new EncryptorBeanDefinitionParser(EncryptorFactoryBean.ENCRYPTOR_TYPE_BIG_INTEGER));       
        registerBeanDefinitionParser("basic-text-encryptor", 
                new UtilEncryptorBeanDefinitionParser(UtilEncryptorBeanDefinitionParser.UTIL_TYPE_BASIC));       
        registerBeanDefinitionParser("strong-text-encryptor", 
                new UtilEncryptorBeanDefinitionParser(UtilEncryptorBeanDefinitionParser.UTIL_TYPE_STRONG));
        
        registerBeanDefinitionParser("digester-config", new DigesterConfigBeanDefinitionParser());
        registerBeanDefinitionParser("byte-digester", 
                new DigesterBeanDefinitionParser(DigesterFactoryBean.DIGESTER_TYPE_BYTE));       
        registerBeanDefinitionParser("string-digester", 
                new DigesterBeanDefinitionParser(DigesterFactoryBean.DIGESTER_TYPE_STRING));       
        registerBeanDefinitionParser("basic-password-encryptor", 
                new UtilDigesterBeanDefinitionParser(UtilDigesterBeanDefinitionParser.UTIL_TYPE_BASIC));       
        registerBeanDefinitionParser("strong-password-encryptor", 
                new UtilDigesterBeanDefinitionParser(UtilDigesterBeanDefinitionParser.UTIL_TYPE_STRONG));       
        registerBeanDefinitionParser("configurable-password-encryptor", 
                new UtilDigesterBeanDefinitionParser(UtilDigesterBeanDefinitionParser.UTIL_TYPE_CONFIGURABLE));       

        registerBeanDefinitionParser("encryptable-properties", new EncryptablePropertiesBeanDefinitionParser());       

        registerBeanDefinitionParser("encryptable-property-placeholder", new EncryptablePropertyPlaceholderBeanDefinitionParser());
        
    }


}
