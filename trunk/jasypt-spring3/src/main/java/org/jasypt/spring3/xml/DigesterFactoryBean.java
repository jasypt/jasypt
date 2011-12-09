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

import java.beans.Statement;
import java.security.Provider;

import org.jasypt.digest.ByteDigester;
import org.jasypt.digest.PooledByteDigester;
import org.jasypt.digest.PooledStringDigester;
import org.jasypt.digest.StandardByteDigester;
import org.jasypt.digest.StandardStringDigester;
import org.jasypt.digest.StringDigester;
import org.jasypt.digest.config.DigesterConfig;
import org.jasypt.salt.SaltGenerator;
import org.springframework.beans.factory.FactoryBean;

/**
 * 
 * @since 1.9.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class DigesterFactoryBean implements FactoryBean {

    static final int DIGESTER_TYPE_BYTE = 0;
    static final int DIGESTER_TYPE_STRING = 1;
    
    private final int digesterType;

    private Object initializedObject = null;
    
    
    private boolean algorithmSet = false;
    private String algorithm = null;
    
    private boolean configSet = false;
    private DigesterConfig config = null;
    
    private boolean iterationsSet = false;
    private Integer iterations = null;

    private boolean invertPositionOfPlainSaltInEncryptionResultsSet = false;
    private Boolean invertPositionOfPlainSaltInEncryptionResults = null;

    private boolean invertPositionOfSaltInMessageBeforeDigestingSet = false;
    private Boolean invertPositionOfSaltInMessageBeforeDigesting = null;
    
    private boolean providerSet = false;
    private Provider provider = null;
    
    private boolean providerNameSet = false;
    private String providerName = null;
    
    private boolean poolSizeSet = false;
    private Integer poolSize = null;
    
    private boolean saltGeneratorSet = false;
    private SaltGenerator saltGenerator = null;
    
    private boolean saltSizeBytesSet = false;
    private Integer saltSizeBytes = null;
    
    private boolean useLenientSaltSizeCheckSet = false;
    private Boolean useLenientSaltSizeCheck = null;
    
    private boolean stringOutputTypeSet = false;
    private String stringOutputType = null;
    
    private boolean unicodeNormalizationIgnoredSet = false;
    private Boolean unicodeNormalizationIgnored = null;
    
    private boolean prefixSet = false;
    private String prefix = null;
    
    private boolean suffixSet = false;
    private String suffix = null;

    
    
    
    public DigesterFactoryBean(final int encryptorType) {
        super();
        this.digesterType = encryptorType;
    }





    public void setAlgorithm(final String algorithm) {
        this.algorithm = algorithm;
        this.algorithmSet = true;
    }

    
    public void setConfig(final DigesterConfig config) {
        this.config = config;
        this.configSet = true;
    }


    public void setIterations(final Integer iterations) {
        this.iterations = iterations;
        this.iterationsSet =  true;
    }


    public void setPoolSize(final Integer poolSize) {
        this.poolSize = poolSize;
        this.poolSizeSet = true;
    }


    public void setProvider(final Provider provider) {
        this.provider = provider;
        this.providerSet = true;
    }

    
    public void setProviderName(final String providerName) {
        this.providerName = providerName;
        this.providerNameSet = true;
    }


    public void setSaltGenerator(final SaltGenerator saltGenerator) {
        this.saltGenerator = saltGenerator;
        this.saltGeneratorSet = true;
    }
    
    
    public void setInvertPositionOfPlainSaltInEncryptionResults(
            final Boolean invertPositionOfPlainSaltInEncryptionResults) {
        this.invertPositionOfPlainSaltInEncryptionResults = invertPositionOfPlainSaltInEncryptionResults;
        this.invertPositionOfPlainSaltInEncryptionResultsSet = true;
    }


    public void setInvertPositionOfSaltInMessageBeforeDigesting(
            final Boolean invertPositionOfSaltInMessageBeforeDigesting) {
        this.invertPositionOfSaltInMessageBeforeDigesting = invertPositionOfSaltInMessageBeforeDigesting;
        this.invertPositionOfSaltInMessageBeforeDigestingSet = true;
    }


    public void setSaltSizeBytes(final Integer saltSizeBytes) {
        this.saltSizeBytes = saltSizeBytes;
        this.saltSizeBytesSet = true;
    }


    public void setUseLenientSaltSizeCheck(final Boolean useLenientSaltSizeCheck) {
        this.useLenientSaltSizeCheck = useLenientSaltSizeCheck;
        this.useLenientSaltSizeCheckSet = true;
    }


    public void setStringOutputType(final String stringOutputType) {
        this.stringOutputType = stringOutputType;
        this.stringOutputTypeSet = true;
    }


    public void setUnicodeNormalizationIgnored(final Boolean unicodeNormalizationIgnored) {
        this.unicodeNormalizationIgnored = unicodeNormalizationIgnored;
        this.unicodeNormalizationIgnoredSet = true;
    }


    public void setPrefix(final String prefix) {
        this.prefix = prefix;
        this.prefixSet = true;
    }


    public void setSuffix(final String suffix) {
        this.suffix = suffix;
        this.suffixSet = true;
    }





    public Object getObject() throws Exception {
        if (this.initializedObject == null) {
            synchronized (this) {
                if (this.initializedObject == null) {

                    Object digester = null;
                    
                    if (isPooled()) {
                        
                        if (this.digesterType == DIGESTER_TYPE_BYTE) {
                            digester = new PooledByteDigester();
                        } else if (this.digesterType == DIGESTER_TYPE_STRING) {
                            digester = new PooledStringDigester();
                        } else  {
                            throw new IllegalArgumentException("Unknown digester type: " + this.digesterType);
                        }
                        
                        if (this.poolSizeSet && this.poolSize != null) {
                            final Statement st = 
                                    new Statement(
                                            digester, 
                                            "setPoolSize", 
                                            new Object[] { this.poolSize });
                            st.execute();
                        }
                        
                    } else {
                        
                        if (this.digesterType == DIGESTER_TYPE_BYTE) {
                            digester = new StandardByteDigester();
                        } else if (this.digesterType == DIGESTER_TYPE_STRING) {
                            digester = new StandardStringDigester();
                        } else  {
                            throw new IllegalArgumentException("Unknown digester type: " + this.digesterType);
                        }
                        
                    }
                    
                    if (this.algorithmSet) {
                        final Statement st = 
                                new Statement(
                                        digester, 
                                        "setAlgorithm", 
                                        new Object[] { this.algorithm });
                        st.execute();
                    }
                    if (this.configSet) {
                        final Statement st = 
                                new Statement(
                                        digester, 
                                        "setConfig", 
                                        new Object[] { this.config });
                        st.execute();
                    }
                    if (this.iterationsSet && this.iterations != null) {
                        final Statement st = 
                                new Statement(
                                        digester, 
                                        "setIterations", 
                                        new Object[] { this.iterations });
                        st.execute();
                    }
                    if (this.invertPositionOfSaltInMessageBeforeDigestingSet && this.invertPositionOfSaltInMessageBeforeDigesting != null) {
                        final Statement st = 
                                new Statement(
                                        digester, 
                                        "setInvertPositionOfSaltInMessageBeforeDigesting", 
                                        new Object[] { this.invertPositionOfSaltInMessageBeforeDigesting });
                        st.execute();
                    }
                    if (this.invertPositionOfPlainSaltInEncryptionResultsSet && this.invertPositionOfPlainSaltInEncryptionResults != null) {
                        final Statement st = 
                                new Statement(
                                        digester, 
                                        "setInvertPositionOfPlainSaltInEncryptionResults", 
                                        new Object[] { this.invertPositionOfPlainSaltInEncryptionResults });
                        st.execute();
                    }
                    if (this.providerSet) {
                        final Statement st = 
                                new Statement(
                                        digester, 
                                        "setProvider", 
                                        new Object[] { this.provider });
                        st.execute();
                    }
                    if (this.providerNameSet) {
                        final Statement st = 
                                new Statement(
                                        digester, 
                                        "setProviderName", 
                                        new Object[] { this.providerName });
                        st.execute();
                    }
                    if (this.saltGeneratorSet) {
                        final Statement st = 
                                new Statement(
                                        digester, 
                                        "setSaltGenerator", 
                                        new Object[] { this.saltGenerator });
                        st.execute();
                    }
                    if (this.saltSizeBytesSet && this.saltSizeBytes != null) {
                        final Statement st = 
                                new Statement(
                                        digester, 
                                        "setSaltSizeBytes", 
                                        new Object[] { this.saltSizeBytes });
                        st.execute();
                    }
                    if (this.useLenientSaltSizeCheckSet && this.useLenientSaltSizeCheck != null) {
                        final Statement st = 
                                new Statement(
                                        digester, 
                                        "setUseLenientSaltSizeCheck", 
                                        new Object[] { this.useLenientSaltSizeCheck });
                        st.execute();
                    }
                    
                    if (digester instanceof StringDigester) {
                        
                        if (this.stringOutputTypeSet) {
                            final Statement st = 
                                    new Statement(
                                            digester, 
                                            "setStringOutputType", 
                                            new Object[] { this.stringOutputType });
                            st.execute();
                        }
                        if (this.unicodeNormalizationIgnoredSet) {
                            final Statement st = 
                                    new Statement(
                                            digester, 
                                            "setUnicodeNormalizationIgnored", 
                                            new Object[] { this.unicodeNormalizationIgnored });
                            st.execute();
                        }
                        if (this.prefixSet) {
                            final Statement st = 
                                    new Statement(
                                            digester, 
                                            "setPrefix", 
                                            new Object[] { this.prefix });
                            st.execute();
                        }
                        if (this.suffixSet) {
                            final Statement st = 
                                    new Statement(
                                            digester, 
                                            "setSuffix", 
                                            new Object[] { this.suffix });
                            st.execute();
                        }
                        
                    }
                    
                    this.initializedObject = digester;
                    
                }
            }
        }
        return this.initializedObject;
    }

    
    
    public Class getObjectType() {
        if (this.digesterType == DIGESTER_TYPE_BYTE) {
            return ByteDigester.class;
        } else if (this.digesterType == DIGESTER_TYPE_STRING) {
            return StringDigester.class;
        } else {
            throw new IllegalArgumentException("Unknown digester type: " + this.digesterType);
        }
    }

    
    
    public boolean isSingleton() {
        return true;
    }
    
    
    
    
    private boolean isPooled() {
        if (this.poolSizeSet && this.poolSize != null) {
            return true;
        }
        if (this.configSet && this.config != null) {
            return this.config.getPoolSize() != null;
        }
        return false;
    }
    


    



}

