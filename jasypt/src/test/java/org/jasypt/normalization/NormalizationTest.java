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

import java.text.Normalizer.Form;

import junit.framework.Assert;
import junit.framework.TestCase;

import com.ibm.icu.text.Normalizer;

public class NormalizationTest extends TestCase {

    
    public void testNormalizationEquivalence() throws Exception {
        
        String msg = "ÁÉÍÓÚÀÈÌÒÙÄËÏÖÜÂÊÎÔÛÑÇÆÅßÐáéíóúàèìòùäëïöüâêîôûnçæåÞØÕÃāăþőŏœűŁňć";

        String norm1 = Normalizer.normalize(msg, Normalizer.NFC);
        String norm2 = java.text.Normalizer.normalize(msg, Form.NFC);

        Assert.assertEquals(norm1, norm2);

        String denorm1 = Normalizer.normalize(msg, Normalizer.NFD);
        String denorm2 = java.text.Normalizer.normalize(msg, Form.NFD);

        Assert.assertEquals(denorm1, denorm2);
        
        String inter1 = java.text.Normalizer.normalize(Normalizer.normalize(msg, Normalizer.NFD), Form.NFC);
        String inter2 = Normalizer.normalize(java.text.Normalizer.normalize(msg, Form.NFD),Normalizer.NFC);
        
        Assert.assertEquals(inter1, inter2);
        Assert.assertEquals(inter1, msg);
        Assert.assertEquals(inter2, msg);
        
    }
    
    
    
}
