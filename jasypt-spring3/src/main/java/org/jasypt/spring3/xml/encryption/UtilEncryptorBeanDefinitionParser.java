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

import org.jasypt.util.text.BasicTextEncryptor;
import org.jasypt.util.text.StrongTextEncryptor;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

/**
 * 
 * @since 1.9.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
final class UtilEncryptorBeanDefinitionParser extends AbstractEncryptionBeanDefinitionParser {

    
    private static final String PARAM_PASSWORD = "password"; 
    
    static final int UTIL_TYPE_BASIC = 0;
    static final int UTIL_TYPE_STRONG = 1;
    
    private final int utilType;
    
    
    UtilEncryptorBeanDefinitionParser(final int utilType) {
        super();
        this.utilType = utilType;
    }

    
    protected Class getBeanClass(final Element element) {
        if (this.utilType == UTIL_TYPE_BASIC) {
            return BasicTextEncryptor.class;
        } else if (this.utilType == UTIL_TYPE_STRONG) {
            return StrongTextEncryptor.class;
        } else {
            throw new IllegalArgumentException("Unknown util type: " + this.utilType);
        }
    }


    protected void doParse(final Element element, final BeanDefinitionBuilder builder) {
        processStringAttribute(element, builder, PARAM_PASSWORD, "password");
    }
    
    
}

