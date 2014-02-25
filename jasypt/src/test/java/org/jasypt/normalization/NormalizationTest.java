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
package org.jasypt.normalization;

import junit.framework.Assert;
import junit.framework.TestCase;

public class NormalizationTest extends TestCase {

    
    public void testNormalizationEquivalence() throws Exception {
        
        org.jasypt.normalization.Normalizer.initializeIcu4j();
        
        boolean executeJavaTextNorm = true;
        try {
            // Tests might not be executed in Java >= 6
            org.jasypt.normalization.Normalizer.initializeJavaTextNormalizer();
        } catch (final Exception e) {
            executeJavaTextNorm = false;
        }
        
        
        final String msg = "ÁÉÍÓÚÀÈÌÒÙÄËÏÖÜÂÊÎÔÛÑÇÆÅßÐáéíóúàèìòùäëïöüâêîôûnçæåÞØÕÃāăþőŏœűŁňć";
        final char[] msgCharArray = msg.toCharArray();

        String norm1 = com.ibm.icu.text.Normalizer.normalize(msg, com.ibm.icu.text.Normalizer.NFC);
        String norm2 = new String(org.jasypt.normalization.Normalizer.normalizeWithIcu4j(msgCharArray));
        String norm3 = (executeJavaTextNorm? new String(org.jasypt.normalization.Normalizer.normalizeWithJavaNormalizer(msgCharArray)) : null);

        Assert.assertEquals(norm1, norm2);
        if (executeJavaTextNorm) {
            Assert.assertEquals(norm2, norm3);
        }
        
    }
    
    
    
}
