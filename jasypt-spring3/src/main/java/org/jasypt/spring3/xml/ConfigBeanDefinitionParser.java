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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.jasypt.encryption.pbe.config.EnvironmentPBEConfig;
import org.jasypt.encryption.pbe.config.EnvironmentStringPBEConfig;
import org.jasypt.encryption.pbe.config.SimplePBEConfig;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

/**
 * 
 * @since 1.9.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
final class ConfigBeanDefinitionParser extends AbstractEncryptionBeanDefinitionParser {

    // simple
    private static final String PARAM_ALGORITHM = "algorithm"; 
    private static final String PARAM_KEY_OBTENTION_ITERATIONS = "key-obtention-iterations"; 
    private static final String PARAM_PASSWORD = "password"; 
    private static final String PARAM_POOL_SIZE = "pool-size"; 
    private static final String PARAM_PROVIDER = "provider"; 
    private static final String PARAM_PROVIDER_CLASS_NAME = "provider-class-name"; 
    private static final String PARAM_PROVIDER_NAME = "provider-name"; 
    private static final String PARAM_SALT_GENERATOR = "salt-generator"; 
    private static final String PARAM_SALT_GENERATOR_CLASS_NAME = "salt-generator-class-name";
    private static final Set PARAMS_SIMPLE =
            new HashSet(Arrays.asList(
                new String[] {
                    PARAM_ALGORITHM,
                    PARAM_KEY_OBTENTION_ITERATIONS,
                    PARAM_PASSWORD,
                    PARAM_POOL_SIZE,
                    PARAM_PROVIDER,
                    PARAM_PROVIDER_CLASS_NAME,
                    PARAM_PROVIDER_NAME,
                    PARAM_SALT_GENERATOR,
                    PARAM_SALT_GENERATOR_CLASS_NAME
                }));

    // string
    private static final String PARAM_STRING_OUTPUT_TYPE = "string-output-type"; 
    private static final Set PARAMS_STRING =
            new HashSet(Arrays.asList(
                new String[] {
                    PARAM_STRING_OUTPUT_TYPE
                }));

    // environment
    private static final String PARAM_ALGORITHM_ENV_NAME = "algorithm-env-name";
    private static final String PARAM_ALGORITHM_SYS_PROPERTY_NAME = "algorithm-sys-property-name";
    private static final String PARAM_KEY_OBTENTION_ITERATIONS_ENV_NAME = "key-obtention-iterations-env-name";
    private static final String PARAM_KEY_OBTENTION_ITERATIONS_SYS_PROPERTY_NAME = "key-obtention-iterations-sys-property-name";
    private static final String PARAM_PASSWORD_ENV_NAME = "password-env-name";
    private static final String PARAM_PASSWORD_SYS_PROPERTY_NAME = "password-sys-property-name";
    private static final String PARAM_POOL_SIZE_ENV_NAME = "pool-size-env-name";
    private static final String PARAM_POOL_SIZE_SYS_PROPERTY_NAME = "pool-size-sys-property-name";
    private static final String PARAM_PROVIDER_CLASS_NAME_ENV_NAME = "provider-class-name-env-name";
    private static final String PARAM_PROVIDER_CLASS_NAME_SYS_PROPERTY_NAME = "provider-class-name-sys-property-name";
    private static final String PARAM_PROVIDER_NAME_ENV_NAME = "provider-name-env-name";
    private static final String PARAM_PROVIDER_NAME_SYS_PROPERTY_NAME = "provider-name-sys-property-name";
    private static final String PARAM_SALT_GENERATOR_CLASS_NAME_ENV_NAME = "salt-generator-class-name-env-name";
    private static final String PARAM_SALT_GENERATOR_CLASS_NAME_SYS_PROPERTY_NAME = "salt-generator-class-name-sys-property-name";
    private static final Set PARAMS_ENVIRONMENT =
            new HashSet(Arrays.asList(
                new String[] {
                    PARAM_ALGORITHM_ENV_NAME,
                    PARAM_ALGORITHM_SYS_PROPERTY_NAME,
                    PARAM_KEY_OBTENTION_ITERATIONS_ENV_NAME,
                    PARAM_KEY_OBTENTION_ITERATIONS_SYS_PROPERTY_NAME,
                    PARAM_PASSWORD_ENV_NAME,
                    PARAM_PASSWORD_SYS_PROPERTY_NAME,
                    PARAM_POOL_SIZE_ENV_NAME,
                    PARAM_POOL_SIZE_SYS_PROPERTY_NAME,
                    PARAM_PROVIDER_CLASS_NAME_ENV_NAME,
                    PARAM_PROVIDER_CLASS_NAME_SYS_PROPERTY_NAME,
                    PARAM_PROVIDER_NAME_ENV_NAME,
                    PARAM_PROVIDER_NAME_SYS_PROPERTY_NAME,
                    PARAM_SALT_GENERATOR_CLASS_NAME_ENV_NAME,
                    PARAM_SALT_GENERATOR_CLASS_NAME_SYS_PROPERTY_NAME
                }));

    // string environment
    private static final String PARAM_STRING_OUTPUT_TYPE_ENV_NAME = "string-output-type-env-name";
    private static final String PARAM_STRING_OUTPUT_TYPE_SYS_PROPERTY_NAME = "string-output-type-sys-property-name";
    private static final Set PARAMS_STRING_ENVIRONMENT =
            new HashSet(Arrays.asList(
                new String[] {
                    PARAM_STRING_OUTPUT_TYPE_ENV_NAME,
                    PARAM_STRING_OUTPUT_TYPE_SYS_PROPERTY_NAME
                }));

    
    
    
    
    
    ConfigBeanDefinitionParser() {
        super();
    }

    
    protected Class getBeanClass(final Element element) {
        return computeConfigClass(element);
    }


    
    
    protected void doParse(final Element element, final BeanDefinitionBuilder builder) {
        
        processStringAttribute(element, builder, PARAM_ALGORITHM, "algorithm");
        processIntegerAttribute(element, builder, PARAM_KEY_OBTENTION_ITERATIONS, "keyObtentionIterations");
        processStringAttribute(element, builder, PARAM_PASSWORD, "password");
        processIntegerAttribute(element, builder, PARAM_POOL_SIZE, "poolSize");
        processBeanAttribute(element, builder, PARAM_PROVIDER, "provider");
        processStringAttribute(element, builder, PARAM_PROVIDER_CLASS_NAME, "providerClassName");
        processStringAttribute(element, builder, PARAM_PROVIDER_NAME, "providerName");
        processBeanAttribute(element, builder, PARAM_SALT_GENERATOR, "saltGenerator");
        processStringAttribute(element, builder, PARAM_SALT_GENERATOR_CLASS_NAME, "saltGeneratorClassName");
        
        processStringAttribute(element, builder, PARAM_STRING_OUTPUT_TYPE, "stringOutputType");

        processStringAttribute(element, builder, PARAM_ALGORITHM_ENV_NAME, "algorithmEnvName");
        processStringAttribute(element, builder, PARAM_KEY_OBTENTION_ITERATIONS_ENV_NAME, "keyObtentionIterationsEnvName");
        processStringAttribute(element, builder, PARAM_PASSWORD_ENV_NAME, "passwordEnvName");
        processStringAttribute(element, builder, PARAM_POOL_SIZE_ENV_NAME, "poolSizeEnvName");
        processStringAttribute(element, builder, PARAM_PROVIDER_CLASS_NAME_ENV_NAME, "providerClassNameEnvName");
        processStringAttribute(element, builder, PARAM_PROVIDER_NAME_ENV_NAME, "providerNameEnvName");
        processStringAttribute(element, builder, PARAM_SALT_GENERATOR_CLASS_NAME_ENV_NAME, "saltGeneratorClassNameEnvName");
        processStringAttribute(element, builder, PARAM_ALGORITHM_SYS_PROPERTY_NAME, "algorithmSysPropertyName");
        processStringAttribute(element, builder, PARAM_KEY_OBTENTION_ITERATIONS_SYS_PROPERTY_NAME, "keyObtentionIterationsSysPropertyName");
        processStringAttribute(element, builder, PARAM_PASSWORD_SYS_PROPERTY_NAME, "passwordSysPropertyName");
        processStringAttribute(element, builder, PARAM_POOL_SIZE_SYS_PROPERTY_NAME, "poolSizeSysPropertyName");
        processStringAttribute(element, builder, PARAM_PROVIDER_CLASS_NAME_SYS_PROPERTY_NAME, "providerClassNameSysPropertyName");
        processStringAttribute(element, builder, PARAM_PROVIDER_NAME_SYS_PROPERTY_NAME, "providerNameSysPropertyName");
        processStringAttribute(element, builder, PARAM_SALT_GENERATOR_CLASS_NAME_SYS_PROPERTY_NAME, "saltGeneratorClassNameSysPropertyName");

        processStringAttribute(element, builder, PARAM_STRING_OUTPUT_TYPE_ENV_NAME, "stringOutputTypeEnvName");
        processStringAttribute(element, builder, PARAM_STRING_OUTPUT_TYPE_SYS_PROPERTY_NAME, "stringOutputTypeSysPropertyName");
        
    }
    
    
    
    
    private static Class computeConfigClass(final Element element) {
        
        boolean isSimpleConfig = false;
        boolean isStringConfig = false;
        boolean isEnvironmentConfig = false;
        boolean isStringEnvironmentConfig = false;

        final NamedNodeMap attributesMap = element.getAttributes();
        final int attributesLen = attributesMap.getLength();
        for (int i = 0; i < attributesLen; i++) {
            final Node attribute = attributesMap.item(i);
            final String attributeName = attribute.getNodeName();
            if (!isSimpleConfig && PARAMS_SIMPLE.contains(attributeName)) {
                isSimpleConfig = true;
            }
            if (!isStringConfig && PARAMS_STRING.contains(attributeName)) {
                isStringConfig = true;
            }
            if (!isEnvironmentConfig && PARAMS_ENVIRONMENT.contains(attributeName)) {
                isEnvironmentConfig = true;
            }
            if (!isStringEnvironmentConfig && PARAMS_STRING_ENVIRONMENT.contains(attributeName)) {
                isStringEnvironmentConfig = true;
            }
        }
        
        if (isStringEnvironmentConfig || (isEnvironmentConfig && isStringConfig)) {
            return EnvironmentStringPBEConfig.class;
        }
        if (isEnvironmentConfig) {
            return EnvironmentPBEConfig.class;
        }
        if (isStringConfig) {
            return SimpleStringPBEConfig.class;
        }
        return SimplePBEConfig.class;
        
    }
    
    
    
}
