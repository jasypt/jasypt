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
package org.jasypt.normalization;


/**
 * <p>
 * Utility for the normalization of Unicode Strings to NFC form. 
 * </p>
 * <p>
 * This class tries to use the <tt>java.text.Normalizer</tt> class in JDK 1.6
 * first and, if it the class is not found (Java version < 6), then it will use
 * the ICU4J <tt>com.ibm.icu.text.Normalizer</tt> class (in this case, a
 * <tt>ClassNotFoundException</tt> will be thrown if ICU4J is not present).
 * </p>
 * 
 * @since 1.5
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public class Normalizer {

    private static final String JDK_NORMALIZER_CLASS_NAME = "java.text.Normalizer";
    
    private static Boolean useJdkNormalizer = null; 

    /**
     * Normalize Unicode-input message to NFC.
     * 
     * @param message the message to be normalized
     * @return the result of the normalization operation
     */
    public static String normalizeToNfc(String message) {
        
        if (useJdkNormalizer == null) {
            // Still not initialized, will try to load the JDK Normalizer.
            try {
                Class.forName(JDK_NORMALIZER_CLASS_NAME);
                useJdkNormalizer = Boolean.TRUE;
            } catch (ClassNotFoundException e) {
                useJdkNormalizer = Boolean.FALSE;
            }
        }
        if (useJdkNormalizer.booleanValue()) {
            return java.text.Normalizer.normalize(message, java.text.Normalizer.Form.NFC);
        }
        return com.ibm.icu.text.Normalizer.normalize(message, com.ibm.icu.text.Normalizer.NFC);
    }
    
    
    private Normalizer() {
        super();
    }
    
}
