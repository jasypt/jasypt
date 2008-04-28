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

/**
 * <p>
 * Implementation for {@link StringPBEConfig} which can retrieve configuration
 * values from environment variables or system properties.
 * </p>
 * <p>
 * The name of the environment variable or system property (JVM property) to
 * query for each parameter can be set with its corresponding 
 * <tt>setXEnvName</tt> or <tt>setXSysProperty</tt> method.
 * </p>
 * <p>
 * As this class extends {@link SimplePBEConfig}, parameter values
 * can be also set with the usual <tt>setX</tt> methods.
 * </p>
 * <p>
 * For any of the configuration parameters, if its value is not configured
 * in any way, a <tt>null</tt> value will be returned by the
 * corresponding <tt>getX</tt> method. 
 * </p>
 * 
 * @since 1.3
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public class EnvironmentStringPBEConfig 
        extends EnvironmentPBEConfig 
        implements StringPBEConfig {
    
    private String stringOutputType = null;
    
    private String stringOutputTypeEnvName = null;

    private String stringOutputTypeSysPropertyName = null;
    

    /**
     * <p>
     * Creates a new <tt>EnvironmentStringPBEConfig</tt> instance.
     * </p>
     */
    public EnvironmentStringPBEConfig() {
        super();
    }



    /**
     * Retrieve the name of the environment variable which value has been
     * loaded as the String output type.
     *   
     * @return the name of the variable
     */
    public String getStringOutputTypeEnvName() {
        return this.stringOutputTypeEnvName;
    }


    /**
     * Set the config object to use the specified environment variable to
     * load the value for the String output type.
     * 
     * @param stringOutputTypeEnvName the name of the environment variable
     */
    public void setStringOutputTypeEnvName(String stringOutputTypeEnvName) {
        this.stringOutputTypeEnvName = stringOutputTypeEnvName;
        if (stringOutputTypeEnvName == null) {
            this.stringOutputType = null;
        } else {
            this.stringOutputTypeSysPropertyName = null;
            this.stringOutputType =
                CommonUtils.getStandardStringOutputType(
                        System.getenv(stringOutputTypeEnvName));
        }
    }


    /**
     * Retrieve the name of the JVM system property which value has been
     * loaded as the String output type.
     *   
     * @return the name of the property
     */
    public String getStringOutputTypeSysPropertyName() {
        return this.stringOutputTypeSysPropertyName;
    }


    /**
     * Set the config object to use the specified JVM system property to
     * load the value for the String output type.
     * 
     * @param stringOutputTypeSysPropertyName the name of the property
     */
    public void setStringOutputTypeSysPropertyName(String stringOutputTypeSysPropertyName) {
        this.stringOutputTypeSysPropertyName = stringOutputTypeSysPropertyName;
        if (stringOutputTypeSysPropertyName == null) {
            this.stringOutputType = null;
        } else {
            this.stringOutputTypeEnvName = null;
            this.stringOutputType =
                CommonUtils.getStandardStringOutputType(
                        System.getProperty(stringOutputTypeSysPropertyName));
        }
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
        this.stringOutputTypeEnvName = null;
        this.stringOutputTypeSysPropertyName = null;
        this.stringOutputType =
            CommonUtils.
                getStandardStringOutputType(stringOutputType);
    }

    
    public String getStringOutputType() {
        return this.stringOutputType;
    }



    
}
