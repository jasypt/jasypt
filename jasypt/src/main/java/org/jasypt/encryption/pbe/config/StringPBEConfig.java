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
package org.jasypt.encryption.pbe.config;



/**
 * <p>
 * Common interface for config classes applicable to 
 * {@link org.jasypt.encryption.pbe.StandardPBEStringEncryptor} objects. 
 * This interface extends {@link PBEConfig} to add config parameters specific 
 * to String encryption. 
 * </p>
 * <p>
 * Objects of classes implementing this interface will provide values for:
 * <ul>
 *   <li>Algorithm.</li>
 *   <li>Security provider (or provider name).</li>
 *   <li>Password.</li>
 *   <li>Hashing iterations for obtaining the encryption key.</li>
 *   <li>Salt generator.</li>
 *   <li>Output type (base64, hexadecimal).</li>
 * </ul>
 * Providing this interface lets the user create new <tt>PBEConfig</tt>
 * classes which retrieve values for this parameters from different
 * (and maybe more secure) sources (remote servers, LDAP, other databases...),
 * and do this transparently for the encryptor object. 
 * </p>
 * <p>
 * The config objects passed to an encryptor <u>will only be queried once</u>
 * for each configuration parameter, and this will happen 
 * during the initialization of the encryptor object. 
 * </p>
 * <p>
 * For a default implementation, see {@link SimpleStringPBEConfig}.
 * </p>
 * 
 * @since 1.3
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public interface StringPBEConfig extends PBEConfig {

    

    /**
     * <p>
     * This parameter lets the user specify the form in which String output
     * will be encoded. Available encoding types are:
     * </p>
     * <ul>
     *   <li><tt><b>base64</b></tt> (default)</li>
     *   <li><tt><b>hexadecimal</b></tt></li>
     * </ul>
     * 
     * @return The name of the encoding type for String output 
     */
    public String getStringOutputType();

    
}
