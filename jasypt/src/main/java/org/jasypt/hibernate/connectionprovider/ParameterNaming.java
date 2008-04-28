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
package org.jasypt.hibernate.connectionprovider;

import org.jasypt.hibernate.encryptor.HibernatePBEEncryptorRegistry;

/**
 * <p>
 * Constant names of the parameters that can be used by a jasypt's 
 * Hibernate connection provider.
 * </p>
 * 
 * @since 1.4
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public class ParameterNaming {

    
    /**
     * Property in <tt>hibernate.cfg.xml</tt> or 
     * <tt>hibernate.properties</tt> which contains the registered name
     * (in {@link HibernatePBEEncryptorRegistry}) of the encryptor which 
     * will be used to decrypt the datasource parameters.
     */
    public static final String ENCRYPTOR_REGISTERED_NAME = 
        "hibernate.connection.encryptor_registered_name";

    
    private ParameterNaming() {
        super();
    }
    
}
