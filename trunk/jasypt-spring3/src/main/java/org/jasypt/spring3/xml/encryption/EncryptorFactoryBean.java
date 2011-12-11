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

import java.beans.Statement;
import java.security.Provider;

import org.jasypt.encryption.pbe.PBEBigDecimalEncryptor;
import org.jasypt.encryption.pbe.PBEBigIntegerEncryptor;
import org.jasypt.encryption.pbe.PBEByteEncryptor;
import org.jasypt.encryption.pbe.PBEStringEncryptor;
import org.jasypt.encryption.pbe.PooledPBEBigDecimalEncryptor;
import org.jasypt.encryption.pbe.PooledPBEBigIntegerEncryptor;
import org.jasypt.encryption.pbe.PooledPBEByteEncryptor;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.StandardPBEBigDecimalEncryptor;
import org.jasypt.encryption.pbe.StandardPBEBigIntegerEncryptor;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.PBEConfig;
import org.jasypt.salt.SaltGenerator;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.InitializingBean;

/**
 * 
 * @since 1.9.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class EncryptorFactoryBean 
        implements FactoryBean<Object>, InitializingBean {

    static final int ENCRYPTOR_TYPE_BYTE = 0;
    static final int ENCRYPTOR_TYPE_STRING = 1;
    static final int ENCRYPTOR_TYPE_BIG_DECIMAL = 2;
    static final int ENCRYPTOR_TYPE_BIG_INTEGER = 3;
    
    private final int encryptorType;

    private boolean singleton = true;
    private Object singletonInstance = null;
    
    
    private boolean algorithmSet = false;
    private String algorithm = null;
    
    private boolean configSet = false;
    private PBEConfig config = null;
    
    private boolean keyObtentionIterationsSet = false;
    private Integer keyObtentionIterations = null;

    private boolean passwordSet = false;
    private String password = null;
    
    private boolean poolSizeSet = false;
    private Integer poolSize = null;
    
    private boolean providerSet = false;
    private Provider provider = null;
    
    private boolean providerNameSet = false;
    private String providerName = null;
    
    private boolean saltGeneratorSet = false;
    private SaltGenerator saltGenerator = null;
    
    private boolean stringOutputTypeSet = false;
    private String stringOutputType = null;

    
    
    
    public EncryptorFactoryBean(final int encryptorType) {
        super();
        this.encryptorType = encryptorType;
    }

    

    public final void setSingleton(boolean singleton) {
        this.singleton = singleton;
    }
    
    
    public final boolean isSingleton() {
        return this.singleton;
    }

    
    
    public void setAlgorithm(final String algorithm) {
        this.algorithm = algorithm;
        this.algorithmSet = true;
    }

    
    public void setConfig(final PBEConfig config) {
        this.config = config;
        this.configSet = true;
    }


    public void setKeyObtentionIterations(final Integer keyObtentionIterations) {
        this.keyObtentionIterations = keyObtentionIterations;
        this.keyObtentionIterationsSet =  true;
    }

    
    public void setPassword(final String password) {
        this.password = password;
        this.passwordSet = true;
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


    public void setStringOutputType(final String stringOutputType) {
        this.stringOutputType = stringOutputType;
        this.stringOutputTypeSet = true;
    }

    
    public final void afterPropertiesSet() throws Exception {
        if (this.singleton) {
            this.singletonInstance = computeObject();
        }
    }


    public Object getObject() throws Exception {
        if (this.singleton) {
            return this.singletonInstance;
        }
        return computeObject();
    }
    
    
    
    private Object computeObject() throws Exception {

        Object encryptor = null;
        
        if (isPooled()) {
            
            if (this.encryptorType == ENCRYPTOR_TYPE_BYTE) {
                encryptor = new PooledPBEByteEncryptor();
            } else if (this.encryptorType == ENCRYPTOR_TYPE_STRING) {
                encryptor = new PooledPBEStringEncryptor();
            } else if (this.encryptorType == ENCRYPTOR_TYPE_BIG_DECIMAL) {
                encryptor = new PooledPBEBigDecimalEncryptor();
            } else if (this.encryptorType == ENCRYPTOR_TYPE_BIG_INTEGER) {
                encryptor = new PooledPBEBigIntegerEncryptor();
            } else  {
                throw new IllegalArgumentException("Unknown encryptor type: " + this.encryptorType);
            }
            
            if (this.poolSizeSet && this.poolSize != null) {
                final Statement st = 
                        new Statement(
                                encryptor, 
                                "setPoolSize", 
                                new Object[] { this.poolSize });
                st.execute();
            }
            
        } else {
            
            if (this.encryptorType == ENCRYPTOR_TYPE_BYTE) {
                encryptor = new StandardPBEByteEncryptor();
            } else if (this.encryptorType == ENCRYPTOR_TYPE_STRING) {
                encryptor = new StandardPBEStringEncryptor();
            } else if (this.encryptorType == ENCRYPTOR_TYPE_BIG_DECIMAL) {
                encryptor = new StandardPBEBigDecimalEncryptor();
            } else if (this.encryptorType == ENCRYPTOR_TYPE_BIG_INTEGER) {
                encryptor = new StandardPBEBigIntegerEncryptor();
            } else  {
                throw new IllegalArgumentException("Unknown encryptor type: " + this.encryptorType);
            }
            
        }
        
        if (this.algorithmSet) {
            final Statement st = 
                    new Statement(
                            encryptor, 
                            "setAlgorithm", 
                            new Object[] { this.algorithm });
            st.execute();
        }
        if (this.configSet) {
            final Statement st = 
                    new Statement(
                            encryptor, 
                            "setConfig", 
                            new Object[] { this.config });
            st.execute();
        }
        if (this.keyObtentionIterationsSet && this.keyObtentionIterations != null) {
            final Statement st = 
                    new Statement(
                            encryptor, 
                            "setKeyObtentionIterations", 
                            new Object[] { this.keyObtentionIterations });
            st.execute();
        }
        if (this.passwordSet) {
            final Statement st = 
                    new Statement(
                            encryptor, 
                            "setPassword", 
                            new Object[] { this.password });
            st.execute();
        }
        if (this.providerSet) {
            final Statement st = 
                    new Statement(
                            encryptor, 
                            "setProvider", 
                            new Object[] { this.provider });
            st.execute();
        }
        if (this.providerNameSet) {
            final Statement st = 
                    new Statement(
                            encryptor, 
                            "setProviderName", 
                            new Object[] { this.providerName });
            st.execute();
        }
        if (this.saltGeneratorSet) {
            final Statement st = 
                    new Statement(
                            encryptor, 
                            "setSaltGenerator", 
                            new Object[] { this.saltGenerator });
            st.execute();
        }
        if (this.stringOutputTypeSet && encryptor instanceof PBEStringEncryptor) {
            final Statement st = 
                    new Statement(
                            encryptor, 
                            "setStringOutputType", 
                            new Object[] { this.stringOutputType });
            st.execute();
        }
        
        return encryptor;

    }

    
    
    public Class<?> getObjectType() {
        if (this.encryptorType == ENCRYPTOR_TYPE_BYTE) {
            return PBEByteEncryptor.class;
        } else if (this.encryptorType == ENCRYPTOR_TYPE_STRING) {
            return PBEStringEncryptor.class;
        } else if (this.encryptorType == ENCRYPTOR_TYPE_BIG_DECIMAL) {
            return PBEBigDecimalEncryptor.class;
        } else if (this.encryptorType == ENCRYPTOR_TYPE_BIG_INTEGER) {
            return PBEBigIntegerEncryptor.class;
        } else {
            throw new IllegalArgumentException("Unknown encryptor type: " + this.encryptorType);
        }
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

