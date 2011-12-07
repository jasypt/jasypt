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
package org.jasypt.spring3.xml;

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
        registerBeanDefinitionParser("encryptor-config", new ConfigBeanDefinitionParser());       
        registerBeanDefinitionParser("byte-encryptor", 
                new EncryptorBeanDefinitionParser(EncryptorBeanDefinitionParser.ENCRYPTOR_TYPE_BYTE));       
        registerBeanDefinitionParser("string-encryptor", 
                new EncryptorBeanDefinitionParser(EncryptorBeanDefinitionParser.ENCRYPTOR_TYPE_STRING));       
        registerBeanDefinitionParser("big-decimal-encryptor", 
                new EncryptorBeanDefinitionParser(EncryptorBeanDefinitionParser.ENCRYPTOR_TYPE_BIG_DECIMAL));       
        registerBeanDefinitionParser("big-integer-encryptor", 
                new EncryptorBeanDefinitionParser(EncryptorBeanDefinitionParser.ENCRYPTOR_TYPE_BIG_INTEGER));       
    }


}
