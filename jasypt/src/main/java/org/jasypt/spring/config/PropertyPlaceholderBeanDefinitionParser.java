/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2008, The JASYPT team (http://www.jasypt.org)
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
package org.jasypt.spring.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;
import org.jasypt.spring.properties.EncryptablePropertyPlaceholderConfigurer;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.EnvironmentPBEConfig;

/**
 * A Bean Definition Parser that can handle the "property-placeholder-env"
 * element of the jasypt schema.  Note that this element is NOT intended to
 * cover all possible configurations, but instead only the most common ones.
 * 
 * @since 1.6
 * 
 * @author Don Brinker
 */
class PropertyPlaceholderBeanDefinitionParser extends AbstractBeanDefinitionParser {

    /**
     * Determine if an ID should be generated instead of read from the passed
     * in {@link org.w3c.dom.Element}?
     *
     * @return  <code>true</code> if the parser should always generate an id,
     *          <code>false</code> otherwise.
     */
    protected boolean shouldGenerateId() {
        return true;
    }

    /**
     * Parse the supplied {@link org.w3c.dom.Element} into one or more
     * {@link org.springframework.beans.factory.config.BeanDefinition
     * BeanDefinitions}.
     *
     * @param element       The element that is to be parsed
     * @param parserContext The object encapsulating the current state of the
     *                      parsing process
     *
     * @return  The primary
     *          {@link org.springframework.beans.factory.config.BeanDefinition}
     */
    protected AbstractBeanDefinition parseInternal(Element element,
                                                   ParserContext parserContext) {
        AbstractBeanDefinition encryptor = getEncryptorDefinition(element);

        BeanDefinitionBuilder builder
            = BeanDefinitionBuilder.rootBeanDefinition(EncryptablePropertyPlaceholderConfigurer.class);
        builder.addConstructorArg(encryptor);
        String location = element.getAttribute("location");
        String[] locations = StringUtils.commaDelimitedListToStringArray(location);
        builder.addPropertyValue("locations", locations);
        builder.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);

        return builder.getBeanDefinition();
    }

    /**
     * Creates the bean definition for the custom encryptor
     *
     * @param element   The XML Element containing the bean definition in the
     *                  custom schema
     *
     * @return  The definition of the encryptor bean
     */
    private AbstractBeanDefinition getEncryptorDefinition(Element element) {
        AbstractBeanDefinition config = getConfigDefinition(element);

        BeanDefinitionBuilder builder
                = BeanDefinitionBuilder.rootBeanDefinition(StandardPBEStringEncryptor.class);
        builder.addPropertyValue("config", config);
        builder.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);

        return builder.getBeanDefinition();
    }

    /**
     * Creates the bean definition for the environment configuration bean
     *
     * @param element   The XML Element containing the bean definition in the
     *                  custom schema
     *
     * @return  The definition of the config bean
     */
    private AbstractBeanDefinition getConfigDefinition(Element element) {
        BeanDefinitionBuilder builder
            = BeanDefinitionBuilder.rootBeanDefinition(EnvironmentPBEConfig.class);
        builder.addPropertyValue("algorithm",
                                 element.getAttribute("algorithm"));

        String envName = element.getAttribute("passwordEnvName");
        if (envName != null) {
            builder.addPropertyValue("passwordEnvName", envName);
        }

        String propertyName = element.getAttribute("systemPropertyName");
        if (propertyName != null) {
            builder.addPropertyValue("passwordSysPropertyName", propertyName);
        }
        builder.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);

        return builder.getBeanDefinition();
    }
}