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
package org.jasypt.encryption.pbe.algorithms;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jasypt.exceptions.EncryptionInitializationException;

public class PBEAlgorithms {

    public static final String PBE_WITH_MD5_AND_DES = 
        "PBEWithMD5AndDES";
    public static final String PBE_WITH_MD5_AND_TRIPLE_DES = 
        "PBEWithMD5AndTripleDES";
    public static final String PBE_WITH_SHA1_AND_DESEDE = 
        "PBEWithSHA1AndDESede";
    public static final String PBE_WITH_SHA1_AND_RC2_40 = 
        "PBEWithSHA1AndRC2_40";
    
    
    private static Map parametersByAlgorithm = new HashMap();
    
    
    static {
        
        addParameters(
                new Parameters(PBE_WITH_MD5_AND_DES, 8)
            );
        addParameters(
                new Parameters(PBE_WITH_MD5_AND_TRIPLE_DES, 8)
            );
        addParameters(
                new Parameters(PBE_WITH_SHA1_AND_DESEDE, 8)
            );
        addParameters(
                new Parameters(PBE_WITH_SHA1_AND_RC2_40, 8)
            );
        
    }
    
    private static void addParameters(Parameters parameters) {
        parametersByAlgorithm.put(parameters.getName(), parameters);
    }
    
    
    public static void validateAlgorithm(String algorithmName) {
        if (getParameters(algorithmName) == null) {
            throw new EncryptionInitializationException(algorithmName +
                    " is not a supported algorithm name");
        }
    }
    
    public static Parameters getParameters(String algorithmName) {
        return (Parameters) parametersByAlgorithm.get(algorithmName);
    }
    
    public static String[] getSupportedAlgorithms() {
        List algorithmNames = new ArrayList(parametersByAlgorithm.keySet());
        Collections.sort(algorithmNames);
        return (String[]) 
                algorithmNames.toArray(new String[algorithmNames.size()]);
    }
    
    
    public static class Parameters {
        
        private String name = null;
        private int saltSizeBytes = 0;
        
        Parameters(String name, int saltSizeBytes) {
            this.name = name;
            this.saltSizeBytes = saltSizeBytes;
        }

        public String getName() {
            return name;
        }

        public int getSaltSizeBytes() {
            return saltSizeBytes;
        }
        
    }
    
}
