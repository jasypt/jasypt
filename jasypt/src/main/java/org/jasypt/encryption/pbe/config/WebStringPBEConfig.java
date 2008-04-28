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
package org.jasypt.encryption.pbe.config;

import org.jasypt.commons.CommonUtils;
import org.jasypt.encryption.pbe.config.StringPBEConfig;


/**
 * <p>
 * Implementation for {@link StringPBEConfig} which can be used from the
 * Web PBE Config infrastructure (Filter + Servlet) to set the
 * password for an encryptor from the web at initialization time.
 * </p>
 * <p>
 * For an encryptor to be assigned a password from the web, it only has
 * to be assigned a WebPBEConfig object, which must be initialized with
 * <b>both</b> a unique name an a validation word. The name will identify
 * the config object (and thus the encryptor) and the validation word will
 * make sure that only an authorized person (for example, the application
 * deployer) sets the passwords.
 * </p>
 * <p>
 * As this class extends {@link SimplePBEConfig}, parameter values
 * can be also set with the usual <tt>setX</tt> methods.
 * </p>
 * <p>
 * For any of the configuration parameters, if its <tt>setX</tt>
 * method is not called, a <tt>null</tt> value will be returned by the
 * corresponding <tt>getX</tt> method. 
 * </p>
 * 
 * @since 1.3
 * 
 * @author Daniel Fern&aacute;ndez
 *
 */
public class WebStringPBEConfig 
        extends WebPBEConfig 
        implements StringPBEConfig {

    private String stringOutputType = null;
    
    
    /**
     * <p>
     * Creates a new <tt>WebStringPBEConfig</tt> instance.
     * </p>
     */
    public WebStringPBEConfig() {
        super();
    }
    
    
    /**
     * <p>
     * Sets the the form in which String output
     * will be encoded. Available encoding types are:
     * </p>
     * <ul>
     *   <li><tt><b>base64</b></tt> (default)</li>
     *   <li><tt><b>hexadecimal</b></tt></li>
     * </ul>
     * <p>
     * If not set, null will be returned.
     * </p>
     * 
     * @param stringOutputType the string output type.
     */
    public void setStringOutputType(String stringOutputType) {
        this.stringOutputType =
            CommonUtils.
                getStandardStringOutputType(stringOutputType);
    }

    
    public String getStringOutputType() {
        return this.stringOutputType;
    }

}
