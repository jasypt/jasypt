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
package org.jasypt.digest.config;


/**
 * <p>
 * Common interface for config classes applicable to 
 * {@link org.jasypt.digest.StandardStringDigester} objects. This interface
 * extends {@link DigesterConfig} to add config parameters specific to
 * String digesting. 
 * </p>
 * <p>
 * Objects of classes implementing this interface will provide values for:
 * <ul>
 *   <li>Algorithm.</li>
 *   <li>Security provider (or provider name).</li>
 *   <li>Salt size (in bytes).</li>
 *   <li>Hashing iterations.</li>
 *   <li>Salt generator.</li>
 *   <li>Use of Unicode normalization mechanisms.</li>
 *   <li>Output type (base64, hexadecimal).</li>
 * </ul>
 * Providing this interface lets the user create new <tt>StringDigesterConfig</tt>
 * classes which retrieve values for this parameters from different
 * (and maybe more secure) sources (remote servers, LDAP, other databases...),
 * and do this transparently for the digester object. 
 * </p>
 * <p>
 * The config objects passed to a digester <u>will only be queried once</u>
 * for each configuration parameter, and this will happen 
 * during the initialization of the digester object. 
 * </p>
 * <p>
 * For a default implementation, see {@link SimpleStringDigesterConfig}.
 * </p>
 * 
 * @since 1.3
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public interface StringDigesterConfig extends DigesterConfig {
    
    
    /**
     * <p>
     * This parameter lets the user specify if the Unicode text normalization
     * step performed during String digest and matching should be ignored.
     * </p>
     * <p>
     * The Java Virtual Machine internally handles all Strings as UNICODE. When
     * digesting or matching digests in jasypt, these Strings are first 
     * <b>normalized to 
     * its NFC form</b> so that digest matching is not affected by the specific
     * form in which the messages where input.
     * </p>
     * <p>
     * <b>It is normally safe (and recommended) to leave this parameter set to 
     * its default FALSE value (and thus DO perform normalization 
     * operations)</b>. But in some specific cases in which issues with legacy
     * software could arise, it might be useful to set this to TRUE.
     * </p>
     * <p>
     * For more information on unicode text normalization, see this issue of 
     * <a href="http://java.sun.com/mailers/techtips/corejava/2007/tt0207.html">Core Java Technologies Tech Tips</a>.
     * </p>
     * 
     * @return whether the unicode text normalization step should be ignored or
     *         not.
     */
    public Boolean isUnicodeNormalizationIgnored();

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
