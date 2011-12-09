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

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

/**
 * 
 * @since 1.9.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
final class DigesterBeanDefinitionParser extends AbstractEncryptionBeanDefinitionParser {

    
    private static final String PARAM_ALGORITHM = "algorithm"; 
    private static final String PARAM_CONFIG_BEAN = "config-bean"; 
    private static final String PARAM_ITERATIONS = "iterations"; 
    private static final String PARAM_SALT_SIZE_BYTES = "salt-size-bytes"; 
    private static final String PARAM_SALT_GENERATOR_BEAN = "salt-generator-bean"; 
    private static final String PARAM_PROVIDER_BEAN = "provider-bean"; 
    private static final String PARAM_PROVIDER_NAME = "provider-name"; 
    private static final String PARAM_INVERT_POSITION_OF_SALT_IN_MESSAGE_BEFORE_DIGESTING = "invert-position-of-salt-in-message-before-digesting"; 
    private static final String PARAM_INVERT_POSITION_OF_PLAIN_SALT_IN_ENCRYPTION_RESULTS = "invert-position-of-plain-salt-in-encryption-results"; 
    private static final String PARAM_USE_LENIENT_SALT_SIZE_CHECK = "use-lenient-salt-size-check"; 
    private static final String PARAM_POOL_SIZE = "pool-size"; 
    
    private static final String PARAM_STRING_OUTPUT_TYPE = "string-output-type"; 
    private static final String PARAM_UNICODE_NORMALIZATION_IGNORED = "unicode-normalization-ignored"; 
    private static final String PARAM_PREFIX = "prefix"; 
    private static final String PARAM_SUFFIX = "suffix"; 
    
    
    private final int digesterType;
    
    
    DigesterBeanDefinitionParser(final int digesterType) {
        super();
        this.digesterType = digesterType;
    }

    
    protected Class getBeanClass(final Element element) {
        return DigesterFactoryBean.class;
    }


    protected void doParse(final Element element, final BeanDefinitionBuilder builder) {
    
        builder.addConstructorArgValue(new Integer(this.digesterType));
        
        processStringAttribute(element, builder, PARAM_ALGORITHM, "algorithm");
        processBeanAttribute(element, builder, PARAM_CONFIG_BEAN, "config");
        processIntegerAttribute(element, builder, PARAM_ITERATIONS, "iterations");
        processIntegerAttribute(element, builder, PARAM_SALT_SIZE_BYTES, "saltSizeBytes");
        processBeanAttribute(element, builder, PARAM_SALT_GENERATOR_BEAN, "saltGenerator");
        processBeanAttribute(element, builder, PARAM_PROVIDER_BEAN, "provider");
        processStringAttribute(element, builder, PARAM_PROVIDER_NAME, "providerName");
        processBooleanAttribute(element, builder, PARAM_INVERT_POSITION_OF_SALT_IN_MESSAGE_BEFORE_DIGESTING, "invertPositionOfSaltInMessageBeforeDigesting");
        processBooleanAttribute(element, builder, PARAM_INVERT_POSITION_OF_PLAIN_SALT_IN_ENCRYPTION_RESULTS, "invertPositionOfPlainSaltInEncryptionResults");
        processBooleanAttribute(element, builder, PARAM_USE_LENIENT_SALT_SIZE_CHECK, "useLenientSaltSizeCheck");
        processIntegerAttribute(element, builder, PARAM_POOL_SIZE, "poolSize");
        
        processStringAttribute(element, builder, PARAM_STRING_OUTPUT_TYPE, "stringOutputType");
        processBooleanAttribute(element, builder, PARAM_UNICODE_NORMALIZATION_IGNORED, "unicodeNormalizationIgnored");
        processStringAttribute(element, builder, PARAM_PREFIX, "prefix");
        processStringAttribute(element, builder, PARAM_SUFFIX, "suffix");
        
    }
    
    
}

