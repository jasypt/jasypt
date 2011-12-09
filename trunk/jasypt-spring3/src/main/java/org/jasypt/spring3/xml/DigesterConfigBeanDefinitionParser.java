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
final class DigesterConfigBeanDefinitionParser extends AbstractEncryptionBeanDefinitionParser {

    // simple
    private static final String PARAM_ALGORITHM = "algorithm"; 
    private static final String PARAM_ITERATIONS = "iterations"; 
    private static final String PARAM_SALT_SIZE_BYTES = "salt-size-bytes"; 
    private static final String PARAM_SALT_GENERATOR_BEAN = "salt-generator-bean"; 
    private static final String PARAM_SALT_GENERATOR_CLASS_NAME = "salt-generator-class-name";
    private static final String PARAM_PROVIDER_BEAN = "provider-bean"; 
    private static final String PARAM_PROVIDER_CLASS_NAME = "provider-class-name"; 
    private static final String PARAM_PROVIDER_NAME = "provider-name"; 
    private static final String PARAM_INVERT_POSITION_OF_SALT_IN_MESSAGE_BEFORE_DIGESTING = "invert-position-of-salt-in-message-before-digesting"; 
    private static final String PARAM_INVERT_POSITION_OF_PLAIN_SALT_IN_ENCRYPTION_RESULTS = "invert-position-of-plain-salt-in-encryption-results"; 
    private static final String PARAM_USE_LENIENT_SALT_SIZE_CHECK = "use-lenient-salt-size-check"; 
    private static final String PARAM_POOL_SIZE = "pool-size"; 
    private static final Set PARAMS_SIMPLE =
            new HashSet(Arrays.asList(
                new String[] {
                    PARAM_ALGORITHM,
                    PARAM_ITERATIONS,
                    PARAM_SALT_SIZE_BYTES,
                    PARAM_SALT_GENERATOR_BEAN,
                    PARAM_SALT_GENERATOR_CLASS_NAME,
                    PARAM_PROVIDER_BEAN,
                    PARAM_PROVIDER_CLASS_NAME,
                    PARAM_PROVIDER_NAME,
                    PARAM_INVERT_POSITION_OF_SALT_IN_MESSAGE_BEFORE_DIGESTING,
                    PARAM_INVERT_POSITION_OF_PLAIN_SALT_IN_ENCRYPTION_RESULTS,
                    PARAM_USE_LENIENT_SALT_SIZE_CHECK,
                    PARAM_POOL_SIZE
                }));

    // string
    private static final String PARAM_STRING_OUTPUT_TYPE = "string-output-type"; 
    private static final String PARAM_UNICODE_NORMALIZATION_IGNORED = "unicode-normalization-ignored"; 
    private static final String PARAM_PREFIX = "prefix"; 
    private static final String PARAM_SUFFIX = "suffix"; 
    private static final Set PARAMS_STRING =
            new HashSet(Arrays.asList(
                new String[] {
                    PARAM_STRING_OUTPUT_TYPE,
                    PARAM_UNICODE_NORMALIZATION_IGNORED,
                    PARAM_PREFIX,
                    PARAM_SUFFIX
                }));

    // environment
    private static final String PARAM_ALGORITHM_ENV_NAME = "algorithm-env-name"; 
    private static final String PARAM_ALGORITHM_SYS_PROPERTY_NAME = "algorithm-sys-property-name"; 
    private static final String PARAM_ITERATIONS_ENV_NAME = "iterations-env-name"; 
    private static final String PARAM_ITERATIONS_SYS_PROPERTY_NAME = "iterations-sys-property-name"; 
    private static final String PARAM_SALT_SIZE_BYTES_ENV_NAME = "salt-size-bytes-env-name"; 
    private static final String PARAM_SALT_SIZE_BYTES_SYS_PROPERTY_NAME = "salt-size-bytes-sys-property-name"; 
    private static final String PARAM_SALT_GENERATOR_CLASS_NAME_ENV_NAME = "salt-generator-class-name-env-name";
    private static final String PARAM_SALT_GENERATOR_CLASS_NAME_SYS_PROPERTY_NAME = "salt-generator-class-name-sys-property-name";
    private static final String PARAM_PROVIDER_CLASS_NAME_ENV_NAME = "provider-class-name-env-name"; 
    private static final String PARAM_PROVIDER_CLASS_NAME_SYS_PROPERTY_NAME = "provider-class-name-sys-property-name"; 
    private static final String PARAM_PROVIDER_NAME_ENV_NAME = "provider-name-env-name"; 
    private static final String PARAM_PROVIDER_NAME_SYS_PROPERTY_NAME = "provider-name-sys-property-name"; 
    private static final String PARAM_INVERT_POSITION_OF_SALT_IN_MESSAGE_BEFORE_DIGESTING_ENV_NAME = "invert-position-of-salt-in-message-before-digesting-env-name"; 
    private static final String PARAM_INVERT_POSITION_OF_SALT_IN_MESSAGE_BEFORE_DIGESTING_SYS_PROPERTY_NAME = "invert-position-of-salt-in-message-before-digesting-sys-property-name"; 
    private static final String PARAM_INVERT_POSITION_OF_PLAIN_SALT_IN_ENCRYPTION_RESULTS_ENV_NAME = "invert-position-of-plain-salt-in-encryption-results-env-name"; 
    private static final String PARAM_INVERT_POSITION_OF_PLAIN_SALT_IN_ENCRYPTION_RESULTS_SYS_PROPERTY_NAME = "invert-position-of-plain-salt-in-encryption-results-sys-property-name"; 
    private static final String PARAM_USE_LENIENT_SALT_SIZE_CHECK_ENV_NAME = "use-lenient-salt-size-check-env-name"; 
    private static final String PARAM_USE_LENIENT_SALT_SIZE_CHECK_SYS_PROPERTY_NAME = "use-lenient-salt-size-check-sys-property-name"; 
    private static final String PARAM_POOL_SIZE_ENV_NAME = "pool-size-env-name"; 
    private static final String PARAM_POOL_SIZE_SYS_PROPERTY_NAME = "pool-size-sys-property-name"; 
    private static final Set PARAMS_ENVIRONMENT =
            new HashSet(Arrays.asList(
                new String[] {
                    PARAM_ALGORITHM_ENV_NAME,
                    PARAM_ALGORITHM_SYS_PROPERTY_NAME,
                    PARAM_ITERATIONS_ENV_NAME,
                    PARAM_ITERATIONS_SYS_PROPERTY_NAME,
                    PARAM_SALT_SIZE_BYTES_ENV_NAME,
                    PARAM_SALT_SIZE_BYTES_SYS_PROPERTY_NAME,
                    PARAM_SALT_GENERATOR_CLASS_NAME_ENV_NAME,
                    PARAM_SALT_GENERATOR_CLASS_NAME_SYS_PROPERTY_NAME,
                    PARAM_PROVIDER_CLASS_NAME_ENV_NAME,
                    PARAM_PROVIDER_CLASS_NAME_SYS_PROPERTY_NAME,
                    PARAM_PROVIDER_NAME_ENV_NAME,
                    PARAM_PROVIDER_NAME_SYS_PROPERTY_NAME,
                    PARAM_INVERT_POSITION_OF_SALT_IN_MESSAGE_BEFORE_DIGESTING_ENV_NAME,
                    PARAM_INVERT_POSITION_OF_SALT_IN_MESSAGE_BEFORE_DIGESTING_SYS_PROPERTY_NAME,
                    PARAM_INVERT_POSITION_OF_PLAIN_SALT_IN_ENCRYPTION_RESULTS_ENV_NAME,
                    PARAM_INVERT_POSITION_OF_PLAIN_SALT_IN_ENCRYPTION_RESULTS_SYS_PROPERTY_NAME,
                    PARAM_USE_LENIENT_SALT_SIZE_CHECK_ENV_NAME,
                    PARAM_USE_LENIENT_SALT_SIZE_CHECK_SYS_PROPERTY_NAME,
                    PARAM_POOL_SIZE_ENV_NAME,
                    PARAM_POOL_SIZE_SYS_PROPERTY_NAME
                }));

    // string environment
    private static final String PARAM_STRING_OUTPUT_TYPE_ENV_NAME = "string-output-type-env-name";
    private static final String PARAM_STRING_OUTPUT_TYPE_SYS_PROPERTY_NAME = "string-output-type-sys-property-name";
    private static final String PARAM_UNICODE_NORMALIZATION_IGNORED_ENV_NAME = "unicode-normalization-ignored-env-name"; 
    private static final String PARAM_UNICODE_NORMALIZATION_IGNORED_SYS_PROPERTY_NAME = "unicode-normalization-ignored-sys-property-name"; 
    private static final String PARAM_PREFIX_ENV_NAME = "prefix-env-name"; 
    private static final String PARAM_PREFIX_SYS_PROPERTY_NAME = "prefix-sys-property-name"; 
    private static final String PARAM_SUFFIX_ENV_NAME = "suffix-env-name"; 
    private static final String PARAM_SUFFIX_SYS_PROPERTY_NAME = "suffix-sys-property-name"; 
    private static final Set PARAMS_STRING_ENVIRONMENT =
            new HashSet(Arrays.asList(
                new String[] {
                    PARAM_STRING_OUTPUT_TYPE_ENV_NAME,
                    PARAM_STRING_OUTPUT_TYPE_SYS_PROPERTY_NAME,
                    PARAM_UNICODE_NORMALIZATION_IGNORED_ENV_NAME,
                    PARAM_UNICODE_NORMALIZATION_IGNORED_SYS_PROPERTY_NAME,
                    PARAM_PREFIX_ENV_NAME,
                    PARAM_PREFIX_SYS_PROPERTY_NAME,
                    PARAM_SUFFIX_ENV_NAME,
                    PARAM_SUFFIX_SYS_PROPERTY_NAME
                }));

    
    
    
    
    
    DigesterConfigBeanDefinitionParser() {
        super();
    }

    
    protected Class getBeanClass(final Element element) {
        return computeConfigClass(element);
    }


    
    
    protected void doParse(final Element element, final BeanDefinitionBuilder builder) {
        
        processStringAttribute(element, builder, PARAM_ALGORITHM, "algorithm");
        processIntegerAttribute(element, builder, PARAM_ITERATIONS, "iterations");
        processIntegerAttribute(element, builder, PARAM_SALT_SIZE_BYTES, "saltSizeBytes");
        processBeanAttribute(element, builder, PARAM_SALT_GENERATOR_BEAN, "saltGenerator");
        processStringAttribute(element, builder, PARAM_SALT_GENERATOR_CLASS_NAME, "saltGeneratorClassName");
        processBeanAttribute(element, builder, PARAM_PROVIDER_BEAN, "provider");
        processStringAttribute(element, builder, PARAM_PROVIDER_CLASS_NAME, "providerClassName");
        processStringAttribute(element, builder, PARAM_PROVIDER_NAME, "providerName");
        processBooleanAttribute(element, builder, PARAM_INVERT_POSITION_OF_SALT_IN_MESSAGE_BEFORE_DIGESTING, "invertPositionOfSaltInMessageBeforeDigesting");
        processBooleanAttribute(element, builder, PARAM_INVERT_POSITION_OF_PLAIN_SALT_IN_ENCRYPTION_RESULTS, "invertPositionOfPlainSaltInEncryptionResults");
        processBooleanAttribute(element, builder, PARAM_USE_LENIENT_SALT_SIZE_CHECK, "useLenientSaltSizeCheck");
        processIntegerAttribute(element, builder, PARAM_POOL_SIZE, "poolSize");
        
        processStringAttribute(element, builder, PARAM_STRING_OUTPUT_TYPE, "stringOutputType");
        processStringAttribute(element, builder, PARAM_UNICODE_NORMALIZATION_IGNORED, "unicodeNormalizationIgnored");
        processStringAttribute(element, builder, PARAM_PREFIX, "prefix");
        processStringAttribute(element, builder, PARAM_SUFFIX, "suffix");

        processStringAttribute(element, builder, PARAM_ALGORITHM_ENV_NAME, "algorithmEnvName");
        processStringAttribute(element, builder, PARAM_ITERATIONS_ENV_NAME, "iterationsEnvName");
        processStringAttribute(element, builder, PARAM_SALT_SIZE_BYTES_ENV_NAME, "saltSizeBytesEnvName");
        processStringAttribute(element, builder, PARAM_SALT_GENERATOR_CLASS_NAME_ENV_NAME, "saltGeneratorClassNameEnvName");
        processStringAttribute(element, builder, PARAM_PROVIDER_CLASS_NAME_ENV_NAME, "providerClassNameEnvName");
        processStringAttribute(element, builder, PARAM_PROVIDER_NAME_ENV_NAME, "providerNameEnvName");
        processStringAttribute(element, builder, PARAM_INVERT_POSITION_OF_SALT_IN_MESSAGE_BEFORE_DIGESTING_ENV_NAME, "invertPositionOfSaltInMessageBeforeDigestingEnvName");
        processStringAttribute(element, builder, PARAM_INVERT_POSITION_OF_PLAIN_SALT_IN_ENCRYPTION_RESULTS_ENV_NAME, "invertPositionOfPlainSaltInEncryptionResultsEnvName");
        processStringAttribute(element, builder, PARAM_USE_LENIENT_SALT_SIZE_CHECK_ENV_NAME, "useLenientSaltSizeCheckEnvName");
        processStringAttribute(element, builder, PARAM_POOL_SIZE_ENV_NAME, "poolSizeEnvName");
        processStringAttribute(element, builder, PARAM_ALGORITHM_SYS_PROPERTY_NAME, "algorithmSysPropertyName");
        processStringAttribute(element, builder, PARAM_ITERATIONS_SYS_PROPERTY_NAME, "iterationsSysPropertyName");
        processStringAttribute(element, builder, PARAM_SALT_SIZE_BYTES_SYS_PROPERTY_NAME, "saltSizeBytesSysPropertyName");
        processStringAttribute(element, builder, PARAM_SALT_GENERATOR_CLASS_NAME_SYS_PROPERTY_NAME, "saltGeneratorClassNameSysPropertyName");
        processStringAttribute(element, builder, PARAM_PROVIDER_CLASS_NAME_SYS_PROPERTY_NAME, "providerClassNameSysPropertyName");
        processStringAttribute(element, builder, PARAM_PROVIDER_NAME_SYS_PROPERTY_NAME, "providerNameSysPropertyName");
        processStringAttribute(element, builder, PARAM_INVERT_POSITION_OF_SALT_IN_MESSAGE_BEFORE_DIGESTING_SYS_PROPERTY_NAME, "invertPositionOfSaltInMessageBeforeDigestingSysPropertyName");
        processStringAttribute(element, builder, PARAM_INVERT_POSITION_OF_PLAIN_SALT_IN_ENCRYPTION_RESULTS_SYS_PROPERTY_NAME, "invertPositionOfPlainSaltInEncryptionResultsSysPropertyName");
        processStringAttribute(element, builder, PARAM_USE_LENIENT_SALT_SIZE_CHECK_SYS_PROPERTY_NAME, "useLenientSaltSizeCheckSysPropertyName");
        processStringAttribute(element, builder, PARAM_POOL_SIZE_SYS_PROPERTY_NAME, "poolSizeSysPropertyName");
        
        processStringAttribute(element, builder, PARAM_STRING_OUTPUT_TYPE_ENV_NAME, "stringOutputTypeEnvName");
        processStringAttribute(element, builder, PARAM_STRING_OUTPUT_TYPE_SYS_PROPERTY_NAME, "stringOutputTypeSysPropertyName");
        processStringAttribute(element, builder, PARAM_UNICODE_NORMALIZATION_IGNORED_ENV_NAME, "unicodeNormalizationIgnoredEnvName");
        processStringAttribute(element, builder, PARAM_UNICODE_NORMALIZATION_IGNORED_SYS_PROPERTY_NAME, "unicodeNormalizationIgnoredSysPropertyName");
        processStringAttribute(element, builder, PARAM_PREFIX_ENV_NAME, "prefixEnvName");
        processStringAttribute(element, builder, PARAM_PREFIX_SYS_PROPERTY_NAME, "prefixSysPropertyName");
        processStringAttribute(element, builder, PARAM_SUFFIX_ENV_NAME, "suffixEnvName");
        processStringAttribute(element, builder, PARAM_SUFFIX_SYS_PROPERTY_NAME, "suffixSysPropertyName");
        
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
