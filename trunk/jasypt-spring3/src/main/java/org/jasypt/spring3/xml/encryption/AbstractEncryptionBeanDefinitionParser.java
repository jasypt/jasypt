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

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * 
 * @since 1.9.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
abstract class AbstractEncryptionBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {
    

    
    protected AbstractEncryptionBeanDefinitionParser() {
        super();
    }
    
    
    
    protected final void processStringAttribute(final Element element, final BeanDefinitionBuilder builder, 
            final String attributeName, final String propertyName) {
        final String attributeValue = element.getAttribute(attributeName);
        if (StringUtils.hasText(attributeValue)) {
            builder.addPropertyValue(propertyName, attributeValue);
        }
    }
    
    
    protected final void processIntegerAttribute(final Element element, final BeanDefinitionBuilder builder, 
            final String attributeName, final String propertyName) {
        final String attributeValue = element.getAttribute(attributeName);
        if (StringUtils.hasText(attributeValue)) {
            try {
                final Integer attributeIntegerValue = Integer.valueOf(attributeValue);
                builder.addPropertyValue(propertyName, attributeIntegerValue);
            } catch (final NumberFormatException e) {
                throw new NumberFormatException(
                        "Config attribute \"" + attributeName + "\" is not a valid integer");
            }
        }
    }
    
    
    protected final void processBooleanAttribute(final Element element, final BeanDefinitionBuilder builder, 
            final String attributeName, final String propertyName) {
        final String attributeValue = element.getAttribute(attributeName);
        if (StringUtils.hasText(attributeValue)) {
            final Boolean attributeBooleanValue =  Boolean.valueOf(attributeValue);
            builder.addPropertyValue(propertyName, attributeBooleanValue);
        }
    }
    
    
    protected final void processBeanAttribute(final Element element, final BeanDefinitionBuilder builder, 
            final String attributeName, final String propertyName) {
        final String beanName = element.getAttribute(attributeName);
        if (StringUtils.hasText(beanName)) {
            builder.addPropertyReference(propertyName, beanName);
        }
    }
    
    
    
}
