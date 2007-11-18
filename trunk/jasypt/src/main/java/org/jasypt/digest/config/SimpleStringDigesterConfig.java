/*
 * =============================================================================
 * 
 *   Copyright (c) 2007, The JASYPT team (http://www.jasypt.org)
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

import org.jasypt.commons.CommonUtils;


/**
 * <p>
 * Bean implementation for {@link StringDigesterConfig}. This class allows 
 * the values for the configuration parameters to be set
 * via "standard" <tt>setX</tt> methods.
 * </p>
 * <p>
 * For any of the configuration parameters, if its <tt>setX</tt>
 * method is not called, a <tt>null</tt> value will be returned by the
 * corresponding <tt>getX</tt> method. 
 * </p>
 * 
 * @since 1.3
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public class SimpleStringDigesterConfig 
        extends SimpleDigesterConfig
        implements StringDigesterConfig {
    
    private Boolean unicodeNormalizationIgnored = null;
    private String stringOutputType = null;
    

    /**
     * <p>
     * Creates a new <tt>SimpleStringDigesterConfig</tt> instance.
     * </p>
     */
    public SimpleStringDigesterConfig() {
        super();
    }
    
    /**
     * <p>
     * Sets whether the unicode text normalization step should be ignored.
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
     * <p>
     * If not set, null will be returned.
     * </p>
     * <p>
     * Determines the result of: {@link #isUnicodeNormalizationIgnored()}
     * </p>
     * 
     * @param unicodeNormalizationIgnored whether the unicode text 
     *        normalization step should be ignored or not.
     */
    public void setUnicodeNormalizationIgnored(Boolean unicodeNormalizationIgnored) {
        this.unicodeNormalizationIgnored = unicodeNormalizationIgnored;
    }

    
    /**
     * <p>
     * Sets whether the unicode text normalization step should be ignored.
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
     * <p>
     * If not set, null will be returned.
     * </p>
     * <p>
     * Determines the result of: {@link #isUnicodeNormalizationIgnored()}
     * </p>
     *
     * @since 1.4
     * 
     * @param unicodeNormalizationIgnored whether the unicode text 
     *        normalization step should be ignored or not.
     */
    public void setUnicodeNormalizationIgnored(String unicodeNormalizationIgnored) {
        if (unicodeNormalizationIgnored != null) {
            this.unicodeNormalizationIgnored = 
                CommonUtils.getStandardBooleanValue(unicodeNormalizationIgnored);
        } else {
            this.unicodeNormalizationIgnored = null;
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
     * <p>
     * Determines the result of: {@link #getStringOutputType()}
     * </p>
     * 
     * @param stringOutputType the string output type.
     */
    public void setStringOutputType(String stringOutputType) {
        this.stringOutputType = 
            CommonUtils.
                getStandardStringOutputType(stringOutputType);
    }

    
    public Boolean isUnicodeNormalizationIgnored() {
        return this.unicodeNormalizationIgnored;
    }

    
    public String getStringOutputType() {
        return this.stringOutputType;
    }

    
}
