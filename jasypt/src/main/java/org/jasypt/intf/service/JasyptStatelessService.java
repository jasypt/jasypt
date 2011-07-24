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
package org.jasypt.intf.service;

import org.jasypt.commons.CommonUtils;
import org.jasypt.digest.StandardStringDigester;
import org.jasypt.digest.config.EnvironmentStringDigesterConfig;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.EnvironmentStringPBEConfig;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;



/**
 * <p>
 * This class acts as a stateless service for encryption, decryption and
 * digest operations, letting its clients configure all the jasypt environment
 * (algorithms, passwords, providers...) from Strings in a single call, be it
 * using direct values, environment variables or java vm properties.
 * </p>
 * <p>
 * It is meant to service the CLI interfaces, but it can also be used for other
 * purposes. For instance, by subclassing or wrapping it with a JAX-WS web 
 * service class, developers can easily create an encryption web service.
 * </p>
 * 
 * @since 1.4
 * 
 * @author Daniel Fern&aacute;ndez
 *
 */
public final class JasyptStatelessService {



    /**
     * Creates a new instance of <tt>JasyptStatelessService</tt>. 
     */
    public JasyptStatelessService() {
        super();
    }
    

    /**
     * <p>
     * Configure and perform a digest operation.
     * </p>
     * 
     * @param input
     * @param algorithm
     * @param algorithmEnvName
     * @param algorithmSysPropertyName
     * @param iterations
     * @param iterationsEnvName
     * @param iterationsSysPropertyName
     * @param saltSizeBytes
     * @param saltSizeBytesEnvName
     * @param saltSizeBytesSysPropertyName
     * @param saltGeneratorClassName
     * @param saltGeneratorClassNameEnvName
     * @param saltGeneratorClassNameSysPropertyName
     * @param providerName
     * @param providerNameEnvName
     * @param providerNameSysPropertyName
     * @param providerClassName
     * @param providerClassNameEnvName
     * @param providerClassNameSysPropertyName
     * @param invertPositionOfSaltInMessageBeforeDigesting
     * @param invertPositionOfSaltInMessageBeforeDigestingEnvName
     * @param invertPositionOfSaltInMessageBeforeDigestingSysPropertyName
     * @param invertPositionOfPlainSaltInEncryptionResults
     * @param invertPositionOfPlainSaltInEncryptionResultsEnvName
     * @param invertPositionOfPlainSaltInEncryptionResultsSysPropertyName
     * @param useLenientSaltSizeCheck
     * @param useLenientSaltSizeCheckEnvName
     * @param useLenientSaltSizeCheckSysPropertyName
     * @param unicodeNormalizationIgnored
     * @param unicodeNormalizationIgnoredEnvName
     * @param unicodeNormalizationIgnoredSysPropertyName
     * @param stringOutputType
     * @param stringOutputTypeEnvName
     * @param stringOutputTypeSysPropertyName
     * @param prefix
     * @param prefixEnvName
     * @param prefixSysPropertyName
     * @param suffix
     * @param suffixEnvName
     * @param suffixSysPropertyName
     * 
     * @return the result of the digest operation
     * @throws EncryptionOperationNotPossibleException if the operation could
     *         not be performed (either because of wrong input or wrong
     *         parametrization).
     */
    public String digest(
            final String input,
            final String algorithm,
            final String algorithmEnvName,
            final String algorithmSysPropertyName,
            final String iterations,
            final String iterationsEnvName,
            final String iterationsSysPropertyName,
            final String saltSizeBytes,
            final String saltSizeBytesEnvName,
            final String saltSizeBytesSysPropertyName,
            final String saltGeneratorClassName, 
            final String saltGeneratorClassNameEnvName,
            final String saltGeneratorClassNameSysPropertyName,
            final String providerName,
            final String providerNameEnvName,
            final String providerNameSysPropertyName,
            final String providerClassName,
            final String providerClassNameEnvName,
            final String providerClassNameSysPropertyName,
            final String invertPositionOfSaltInMessageBeforeDigesting,
            final String invertPositionOfSaltInMessageBeforeDigestingEnvName,
            final String invertPositionOfSaltInMessageBeforeDigestingSysPropertyName,
            final String invertPositionOfPlainSaltInEncryptionResults,
            final String invertPositionOfPlainSaltInEncryptionResultsEnvName,
            final String invertPositionOfPlainSaltInEncryptionResultsSysPropertyName,
            final String useLenientSaltSizeCheck,
            final String useLenientSaltSizeCheckEnvName,
            final String useLenientSaltSizeCheckSysPropertyName,
            final String unicodeNormalizationIgnored, 
            final String unicodeNormalizationIgnoredEnvName, 
            final String unicodeNormalizationIgnoredSysPropertyName, 
            final String stringOutputType,
            final String stringOutputTypeEnvName,
            final String stringOutputTypeSysPropertyName,
            final String prefix,
            final String prefixEnvName,
            final String prefixSysPropertyName,
            final String suffix,
            final String suffixEnvName,
            final String suffixSysPropertyName) {

        
        final EnvironmentStringDigesterConfig config = 
            new EnvironmentStringDigesterConfig();
        
        if (algorithmEnvName != null) {
            config.setAlgorithmEnvName(algorithmEnvName);
        }
        if (algorithmSysPropertyName != null) {
            config.setAlgorithmSysPropertyName(algorithmSysPropertyName);
        }
        if (algorithm != null) {
            config.setAlgorithm(algorithm);
        }
        
        if (iterationsEnvName != null) {
            config.setIterationsEnvName(iterationsEnvName);
        }
        if (iterationsSysPropertyName != null) {
            config.setIterationsSysPropertyName(iterationsSysPropertyName);
        }
        if (iterations != null) {
            config.setIterations(iterations);
        }
        
        if (saltSizeBytesEnvName != null) {
            config.setSaltSizeBytesEnvName(saltSizeBytesEnvName);
        }
        if (saltSizeBytesSysPropertyName != null) {
            config.setSaltSizeBytesSysPropertyName(saltSizeBytesSysPropertyName);
        }
        if (saltSizeBytes != null) {
            config.setSaltSizeBytes(saltSizeBytes);
        }
        
        if (saltGeneratorClassNameEnvName != null) {
            config.setSaltGeneratorClassNameEnvName(
                    saltGeneratorClassNameEnvName);
        }
        if (saltGeneratorClassNameSysPropertyName != null) {
            config.setSaltGeneratorClassNameSysPropertyName(
                    saltGeneratorClassNameSysPropertyName);
        }
        if (saltGeneratorClassName != null) {
            config.setSaltGeneratorClassName(saltGeneratorClassName);
        }
        
        if (providerNameEnvName != null) {
            config.setProviderNameEnvName(providerNameEnvName);
        }
        if (providerNameSysPropertyName != null) {
            config.setProviderNameSysPropertyName(providerNameSysPropertyName);
        }
        if (providerName != null) {
            config.setProviderName(providerName);
        }
        
        if (providerClassNameEnvName != null) {
            config.setProviderClassNameEnvName(providerClassNameEnvName);
        }
        if (providerClassNameSysPropertyName != null) {
            config.setProviderClassNameSysPropertyName(
                    providerClassNameSysPropertyName);
        }
        if (providerClassName != null) {
            config.setProviderClassName(providerClassName);
        }
        
        if (invertPositionOfSaltInMessageBeforeDigestingEnvName != null) {
            config.setInvertPositionOfSaltInMessageBeforeDigestingEnvName(invertPositionOfSaltInMessageBeforeDigestingEnvName);
        }
        if (invertPositionOfSaltInMessageBeforeDigestingSysPropertyName != null) {
            config.setInvertPositionOfSaltInMessageBeforeDigestingSysPropertyName(
                    invertPositionOfSaltInMessageBeforeDigestingSysPropertyName);
        }
        if (invertPositionOfSaltInMessageBeforeDigesting != null) {
            config.setInvertPositionOfSaltInMessageBeforeDigesting(
                    CommonUtils.getStandardBooleanValue(invertPositionOfSaltInMessageBeforeDigesting));
        }
        
        if (invertPositionOfPlainSaltInEncryptionResultsEnvName != null) {
            config.setInvertPositionOfPlainSaltInEncryptionResultsEnvName(invertPositionOfPlainSaltInEncryptionResultsEnvName);
        }
        if (invertPositionOfPlainSaltInEncryptionResultsSysPropertyName != null) {
            config.setInvertPositionOfPlainSaltInEncryptionResultsSysPropertyName(
                    invertPositionOfPlainSaltInEncryptionResultsSysPropertyName);
        }
        if (invertPositionOfPlainSaltInEncryptionResults != null) {
            config.setInvertPositionOfPlainSaltInEncryptionResults(
                    CommonUtils.getStandardBooleanValue(invertPositionOfPlainSaltInEncryptionResults));
        }
        
        if (useLenientSaltSizeCheckEnvName != null) {
            config.setUseLenientSaltSizeCheckEnvName(useLenientSaltSizeCheckEnvName);
        }
        if (useLenientSaltSizeCheckSysPropertyName != null) {
            config.setUseLenientSaltSizeCheckSysPropertyName(
                    useLenientSaltSizeCheckSysPropertyName);
        }
        if (useLenientSaltSizeCheck != null) {
            config.setUseLenientSaltSizeCheck(
                    CommonUtils.getStandardBooleanValue(useLenientSaltSizeCheck));
        }
        
        if (unicodeNormalizationIgnoredEnvName != null) {
            config.setUnicodeNormalizationIgnoredEnvName(
                    unicodeNormalizationIgnoredEnvName);
        }
        if (unicodeNormalizationIgnoredSysPropertyName != null) {
            config.setUnicodeNormalizationIgnoredSysPropertyName(
                    unicodeNormalizationIgnoredSysPropertyName);
        }
        if (unicodeNormalizationIgnored != null) {
            config.setUnicodeNormalizationIgnored(unicodeNormalizationIgnored);
        }
        
        if (stringOutputTypeEnvName != null) {
            config.setStringOutputTypeEnvName(stringOutputTypeEnvName);
        }
        if (stringOutputTypeSysPropertyName != null) {
            config.setStringOutputTypeSysPropertyName(
                    stringOutputTypeSysPropertyName);
        }
        if (stringOutputType != null) {
            config.setStringOutputType(stringOutputType);
        }
        
        if (prefixEnvName != null) {
            config.setPrefixEnvName(prefixEnvName);
        }
        if (prefixSysPropertyName != null) {
            config.setPrefixSysPropertyName(
                    prefixSysPropertyName);
        }
        if (prefix != null) {
            config.setPrefix(prefix);
        }
        
        if (suffixEnvName != null) {
            config.setSuffixEnvName(suffixEnvName);
        }
        if (suffixSysPropertyName != null) {
            config.setSuffixSysPropertyName(
                    suffixSysPropertyName);
        }
        if (suffix != null) {
            config.setSuffix(suffix);
        }
        
        
        final StandardStringDigester digester = new StandardStringDigester();
        digester.setConfig(config);
        
        return digester.digest(input);
        
    }

    
    /**
     * <p>
     * Configure and perform an encryption operation.
     * </p>
     * 
     * @param input
     * @param password
     * @param passwordEnvName
     * @param passwordSysPropertyName
     * @param algorithm
     * @param algorithmEnvName
     * @param algorithmSysPropertyName
     * @param keyObtentionIterations
     * @param keyObtentionIterationsEnvName
     * @param keyObtentionIterationsSysPropertyName
     * @param saltGeneratorClassName
     * @param saltGeneratorClassNameEnvName
     * @param saltGeneratorClassNameSysPropertyName
     * @param providerName
     * @param providerNameEnvName
     * @param providerNameSysPropertyName
     * @param providerClassName
     * @param providerClassNameEnvName
     * @param providerClassNameSysPropertyName
     * @param stringOutputType
     * @param stringOutputTypeEnvName
     * @param stringOutputTypeSysPropertyName
     * @return the result of the encryption operation
     * @throws EncryptionOperationNotPossibleException if the operation could
     *         not be performed (either because of wrong input or wrong
     *         parametrization).
     */
    public String encrypt(
            final String input,
            final String password,
            final String passwordEnvName,
            final String passwordSysPropertyName,
            final String algorithm,
            final String algorithmEnvName,
            final String algorithmSysPropertyName,
            final String keyObtentionIterations,
            final String keyObtentionIterationsEnvName,
            final String keyObtentionIterationsSysPropertyName,
            final String saltGeneratorClassName, 
            final String saltGeneratorClassNameEnvName,
            final String saltGeneratorClassNameSysPropertyName,
            final String providerName,
            final String providerNameEnvName,
            final String providerNameSysPropertyName,
            final String providerClassName,
            final String providerClassNameEnvName,
            final String providerClassNameSysPropertyName,
            final String stringOutputType,
            final String stringOutputTypeEnvName,
            final String stringOutputTypeSysPropertyName) {

        
        final EnvironmentStringPBEConfig config = 
            new EnvironmentStringPBEConfig();
        
        if (algorithmEnvName != null) {
            config.setAlgorithmEnvName(algorithmEnvName);
        }
        if (algorithmSysPropertyName != null) {
            config.setAlgorithmSysPropertyName(algorithmSysPropertyName);
        }
        if (algorithm != null) {
            config.setAlgorithm(algorithm);
        }
        
        if (keyObtentionIterationsEnvName != null) {
            config.setKeyObtentionIterationsEnvName(
                    keyObtentionIterationsEnvName);
        }
        if (keyObtentionIterationsSysPropertyName != null) {
            config.setKeyObtentionIterationsSysPropertyName(
                    keyObtentionIterationsSysPropertyName);
        }
        if (keyObtentionIterations != null) {
            config.setKeyObtentionIterations(keyObtentionIterations);
        }
        
        if (passwordEnvName != null) {
            config.setPasswordEnvName(passwordEnvName);
        }
        if (passwordSysPropertyName != null) {
            config.setPasswordSysPropertyName(passwordSysPropertyName);
        }
        if (password != null) {
            config.setPassword(password);
        }
        
        if (saltGeneratorClassNameEnvName != null) {
            config.setSaltGeneratorClassNameEnvName(
                    saltGeneratorClassNameEnvName);
        }
        if (saltGeneratorClassNameSysPropertyName != null) {
            config.setSaltGeneratorClassNameSysPropertyName(
                    saltGeneratorClassNameSysPropertyName);
        }
        if (saltGeneratorClassName != null) {
            config.setSaltGeneratorClassName(saltGeneratorClassName);
        }
        
        if (providerNameEnvName != null) {
            config.setProviderNameEnvName(providerNameEnvName);
        }
        if (providerNameSysPropertyName != null) {
            config.setProviderNameSysPropertyName(providerNameSysPropertyName);
        }
        if (providerName != null) {
            config.setProviderName(providerName);
        }
        
        if (providerClassNameEnvName != null) {
            config.setProviderClassNameEnvName(providerClassNameEnvName);
        }
        if (providerClassNameSysPropertyName != null) {
            config.setProviderClassNameSysPropertyName(
                    providerClassNameSysPropertyName);
        }
        if (providerClassName != null) {
            config.setProviderClassName(providerClassName);
        }
        
        if (stringOutputTypeEnvName != null) {
            config.setStringOutputTypeEnvName(stringOutputTypeEnvName);
        }
        if (stringOutputTypeSysPropertyName != null) {
            config.setStringOutputTypeSysPropertyName(
                    stringOutputTypeSysPropertyName);
        }
        if (stringOutputType != null) {
            config.setStringOutputType(stringOutputType);
        }
        
        
        final StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setConfig(config);
        
        return encryptor.encrypt(input);
        
    }
    

    /**
     * <p>
     * Configure and perform a decryption operation.
     * </p>
     * 
     * @param input
     * @param password
     * @param passwordEnvName
     * @param passwordSysPropertyName
     * @param algorithm
     * @param algorithmEnvName
     * @param algorithmSysPropertyName
     * @param keyObtentionIterations
     * @param keyObtentionIterationsEnvName
     * @param keyObtentionIterationsSysPropertyName
     * @param saltGeneratorClassName
     * @param saltGeneratorClassNameEnvName
     * @param saltGeneratorClassNameSysPropertyName
     * @param providerName
     * @param providerNameEnvName
     * @param providerNameSysPropertyName
     * @param providerClassName
     * @param providerClassNameEnvName
     * @param providerClassNameSysPropertyName
     * @param stringOutputType
     * @param stringOutputTypeEnvName
     * @param stringOutputTypeSysPropertyName
     * @return the result of the decryption operation
     * @throws EncryptionOperationNotPossibleException if the operation could
     *         not be performed (either because of wrong input or wrong
     *         parametrization).
     */
    public String decrypt(
            final String input,
            final String password,
            final String passwordEnvName,
            final String passwordSysPropertyName,
            final String algorithm,
            final String algorithmEnvName,
            final String algorithmSysPropertyName,
            final String keyObtentionIterations,
            final String keyObtentionIterationsEnvName,
            final String keyObtentionIterationsSysPropertyName,
            final String saltGeneratorClassName, 
            final String saltGeneratorClassNameEnvName,
            final String saltGeneratorClassNameSysPropertyName,
            final String providerName,
            final String providerNameEnvName,
            final String providerNameSysPropertyName,
            final String providerClassName,
            final String providerClassNameEnvName,
            final String providerClassNameSysPropertyName,
            final String stringOutputType,
            final String stringOutputTypeEnvName,
            final String stringOutputTypeSysPropertyName) {

        
        final EnvironmentStringPBEConfig config = 
            new EnvironmentStringPBEConfig();
        
        if (algorithmEnvName != null) {
            config.setAlgorithmEnvName(algorithmEnvName);
        }
        if (algorithmSysPropertyName != null) {
            config.setAlgorithmSysPropertyName(algorithmSysPropertyName);
        }
        if (algorithm != null) {
            config.setAlgorithm(algorithm);
        }
        
        if (keyObtentionIterationsEnvName != null) {
            config.setKeyObtentionIterationsEnvName(
                    keyObtentionIterationsEnvName);
        }
        if (keyObtentionIterationsSysPropertyName != null) {
            config.setKeyObtentionIterationsSysPropertyName(
                    keyObtentionIterationsSysPropertyName);
        }
        if (keyObtentionIterations != null) {
            config.setKeyObtentionIterations(keyObtentionIterations);
        }
        
        if (passwordEnvName != null) {
            config.setPasswordEnvName(passwordEnvName);
        }
        if (passwordSysPropertyName != null) {
            config.setPasswordSysPropertyName(passwordSysPropertyName);
        }
        if (password != null) {
            config.setPassword(password);
        }
        
        if (saltGeneratorClassNameEnvName != null) {
            config.setSaltGeneratorClassNameEnvName(
                    saltGeneratorClassNameEnvName);
        }
        if (saltGeneratorClassNameSysPropertyName != null) {
            config.setSaltGeneratorClassNameSysPropertyName(
                    saltGeneratorClassNameSysPropertyName);
        }
        if (saltGeneratorClassName != null) {
            config.setSaltGeneratorClassName(saltGeneratorClassName);
        }
        
        if (providerNameEnvName != null) {
            config.setProviderNameEnvName(providerNameEnvName);
        }
        if (providerNameSysPropertyName != null) {
            config.setProviderNameSysPropertyName(providerNameSysPropertyName);
        }
        if (providerName != null) {
            config.setProviderName(providerName);
        }
        
        if (providerClassNameEnvName != null) {
            config.setProviderClassNameEnvName(providerClassNameEnvName);
        }
        if (providerClassNameSysPropertyName != null) {
            config.setProviderClassNameSysPropertyName(
                    providerClassNameSysPropertyName);
        }
        if (providerClassName != null) {
            config.setProviderClassName(providerClassName);
        }
        
        if (stringOutputTypeEnvName != null) {
            config.setStringOutputTypeEnvName(stringOutputTypeEnvName);
        }
        if (stringOutputTypeSysPropertyName != null) {
            config.setStringOutputTypeSysPropertyName(
                    stringOutputTypeSysPropertyName);
        }
        if (stringOutputType != null) {
            config.setStringOutputType(stringOutputType);
        }
        
        
        final StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setConfig(config);
        
        return encryptor.decrypt(input);
        
    }
    
}
