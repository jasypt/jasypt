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

import org.jasypt.encryption.pbe.PooledPBEBigDecimalEncryptor;
import org.jasypt.encryption.pbe.PooledPBEBigIntegerEncryptor;
import org.jasypt.encryption.pbe.PooledPBEByteEncryptor;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.StandardPBEBigDecimalEncryptor;
import org.jasypt.encryption.pbe.StandardPBEBigIntegerEncryptor;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

/**
 * 
 * @since 1.9.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
final class EncryptorBeanDefinitionParser extends AbstractEncryptionBeanDefinitionParser {

    static final int ENCRYPTOR_TYPE_BYTE = 0;
    static final int ENCRYPTOR_TYPE_STRING = 1;
    static final int ENCRYPTOR_TYPE_BIG_DECIMAL = 2;
    static final int ENCRYPTOR_TYPE_BIG_INTEGER = 3;

    
    private static final String PARAM_ALGORITHM = "algorithm"; 
    private static final String PARAM_CONFIG_BEAN = "config-bean"; 
    private static final String PARAM_KEY_OBTENTION_ITERATIONS = "key-obtention-iterations"; 
    private static final String PARAM_PASSWORD = "password"; 
    private static final String PARAM_POOL_SIZE = "pool-size"; 
    private static final String PARAM_PROVIDER_BEAN = "provider-bean"; 
    private static final String PARAM_PROVIDER_NAME = "provider-name"; 
    private static final String PARAM_SALT_GENERATOR_BEAN = "salt-generator-bean"; 
    private static final String PARAM_STRING_OUTPUT_TYPE = "string-output-type"; 
    
    
    private final int encryptorType;
    
    
    EncryptorBeanDefinitionParser(final int encryptorType) {
        super();
        this.encryptorType = encryptorType;
    }

    
    protected Class getBeanClass(final Element element) {
        return computeConfigClass(element, this.encryptorType);
    }


    protected void doParse(final Element element, final BeanDefinitionBuilder builder) {
        
        processStringAttribute(element, builder, PARAM_ALGORITHM, "algorithm");
        processBeanAttribute(element, builder, PARAM_CONFIG_BEAN, "config");
        processIntegerAttribute(element, builder, PARAM_KEY_OBTENTION_ITERATIONS, "keyObtentionIterations");
        processStringAttribute(element, builder, PARAM_PASSWORD, "password");
        processIntegerAttribute(element, builder, PARAM_POOL_SIZE, "poolSize");
        processBeanAttribute(element, builder, PARAM_PROVIDER_BEAN, "provider");
        processStringAttribute(element, builder, PARAM_PROVIDER_NAME, "providerName");
        processBeanAttribute(element, builder, PARAM_SALT_GENERATOR_BEAN, "saltGenerator");
        
        processStringAttribute(element, builder, PARAM_STRING_OUTPUT_TYPE, "stringOutputType");
        
    }
    

    private static Class computeConfigClass(final Element element, final int encryptorType) {
        
        boolean isPooled = false;
        
        if (element.hasAttribute(PARAM_POOL_SIZE)) {
            isPooled = true;
        } else if (element.hasAttribute(PARAM_CONFIG_BEAN)){
           final String configBeanName = element.getAttribute(PARAM_CONFIG_BEAN);
           // TODO Obtain config bean, check its "pool-size" property if possible
        }
        
        if (encryptorType == ENCRYPTOR_TYPE_BYTE) {
            if (isPooled) {
                return PooledPBEByteEncryptor.class;
            }
            return StandardPBEByteEncryptor.class;
        } else if (encryptorType == ENCRYPTOR_TYPE_STRING) {
            if (isPooled) {
                return PooledPBEStringEncryptor.class;
            }
            return StandardPBEStringEncryptor.class;
        } else if (encryptorType == ENCRYPTOR_TYPE_BIG_DECIMAL) {
            if (isPooled) {
                return PooledPBEBigDecimalEncryptor.class;
            }
            return StandardPBEBigDecimalEncryptor.class;
        } else if (encryptorType == ENCRYPTOR_TYPE_BIG_INTEGER) {
            if (isPooled) {
                return PooledPBEBigIntegerEncryptor.class;
            }
            return StandardPBEBigIntegerEncryptor.class;
        } 
        
        throw new IllegalArgumentException("Unknown encryptor type: " + encryptorType);
        
    }
    
    
    
}

