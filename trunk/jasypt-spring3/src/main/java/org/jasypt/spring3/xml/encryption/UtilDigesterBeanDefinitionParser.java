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

import org.jasypt.util.password.BasicPasswordEncryptor;
import org.jasypt.util.password.ConfigurablePasswordEncryptor;
import org.jasypt.util.password.StrongPasswordEncryptor;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * 
 * @since 1.9.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
final class UtilDigesterBeanDefinitionParser extends AbstractEncryptionBeanDefinitionParser {

    private static final String SCOPE_ATTRIBUTE = "scope";
    
    private static final String PARAM_ALGORITHM = "algorithm"; 
    private static final String PARAM_CONFIG_BEAN = "config-bean"; 
    private static final String PARAM_PROVIDER_BEAN = "provider-bean"; 
    private static final String PARAM_PROVIDER_NAME = "provider-name"; 
    private static final String PARAM_STRING_OUTPUT_TYPE = "string-output-type"; 
    
    static final int UTIL_TYPE_BASIC = 0;
    static final int UTIL_TYPE_STRONG = 1;
    static final int UTIL_TYPE_CONFIGURABLE = 2;
    
    private final int utilType;
    
    
    UtilDigesterBeanDefinitionParser(final int utilType) {
        super();
        this.utilType = utilType;
    }

    
    protected Class getBeanClass(final Element element) {
        if (this.utilType == UTIL_TYPE_BASIC) {
            return BasicPasswordEncryptor.class;
        } else if (this.utilType == UTIL_TYPE_STRONG) {
            return StrongPasswordEncryptor.class;
        } else if (this.utilType == UTIL_TYPE_CONFIGURABLE) {
            return ConfigurablePasswordEncryptor.class;
        } else {
            throw new IllegalArgumentException("Unknown util type: " + this.utilType);
        }
    }


    protected void doParse(final Element element, final BeanDefinitionBuilder builder) {
        
        processStringAttribute(element, builder, PARAM_ALGORITHM, "algorithm");
        processBeanAttribute(element, builder, PARAM_CONFIG_BEAN, "config");
        processBeanAttribute(element, builder, PARAM_PROVIDER_BEAN, "provider");
        processStringAttribute(element, builder, PARAM_PROVIDER_NAME, "providerName");
        processStringAttribute(element, builder, PARAM_STRING_OUTPUT_TYPE, "stringOutputType");
        
        String scope = element.getAttribute(SCOPE_ATTRIBUTE);
        if (StringUtils.hasLength(scope)) {
            builder.setScope(scope);
        }
        
    }
    
    
}

