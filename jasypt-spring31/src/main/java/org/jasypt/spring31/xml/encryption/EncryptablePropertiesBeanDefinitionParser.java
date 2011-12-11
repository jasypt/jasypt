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
package org.jasypt.spring31.xml.encryption;

import java.util.Properties;

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSimpleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * 
 * @since 1.9.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
final class EncryptablePropertiesBeanDefinitionParser extends AbstractSimpleBeanDefinitionParser {


    private static final String SCOPE_ATTRIBUTE = "scope";
    private static final String ENCRYPTOR_ATTRIBUTE = "encryptor";
    
    
    EncryptablePropertiesBeanDefinitionParser() {
        super();
    }


    @Override
    protected boolean isEligibleAttribute(final String attributeName) {
        return super.isEligibleAttribute(attributeName) && 
                !SCOPE_ATTRIBUTE.equals(attributeName) &&
                !ENCRYPTOR_ATTRIBUTE.equals(attributeName);
    }

    
    @Override
    protected Class<?> getBeanClass(final Element element) {
        return EncryptablePropertiesFactoryBean.class;
    }


    @Override
    protected void doParse(final Element element, final ParserContext parserContext, final BeanDefinitionBuilder builder) {
        super.doParse(element, parserContext, builder);
        Properties parsedProps = parserContext.getDelegate().parsePropsElement(element);
        builder.addPropertyValue("properties", parsedProps);
        String scope = element.getAttribute(SCOPE_ATTRIBUTE);
        if (StringUtils.hasLength(scope)) {
            builder.setScope(scope);
        }
        final String encryptorBeanName = element.getAttribute(ENCRYPTOR_ATTRIBUTE);
        if (StringUtils.hasText(encryptorBeanName)) {
            builder.addPropertyReference("encryptor", encryptorBeanName);
        }
    }
    
    
}

