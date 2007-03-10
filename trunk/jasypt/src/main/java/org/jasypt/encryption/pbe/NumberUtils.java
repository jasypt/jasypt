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
package org.jasypt.encryption.pbe;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.Validate;

/**
 * 
 * Utils for processing numbers in encryptors. Intended only for internal
 * use within jasypt.
 * 
 * @since 1.2
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 *
 */
class NumberUtils {

    
    static byte[] byteArrayFromInt(int number) {
        byte b0 = (byte) (0xff & number);
        byte b1 = (byte) (0xff & (number >> 8));
        byte b2 = (byte) (0xff & (number >> 16));
        byte b3 = (byte) (0xff & (number >> 24));
        return new byte[] {b3,b2,b1,b0};
    }
   
   
    static int intFromByteArray(byte[] byteArray) {
        Validate.isTrue (((byteArray != null) && (byteArray.length > 0)),
                "Cannot convert an empty array into an int");
        int result = (0xff & byteArray[0]);
        for (int i = 0; i < byteArray.length; i++) {
            result = (result << 8) | (0xff & byteArray[i]);
        }
        return result;
    }

    
    static byte[] processBigIntegerEncryptedByteArray(
            byte[] byteArray, int signum) {

        byteArray = ArrayUtils.clone(byteArray);
        
        // Check size
        if (byteArray.length > 4) {
            
            int initialSize = byteArray.length;
            byte[] encryptedMessageExpectedSizeBytes =
                ArrayUtils.subarray(byteArray,
                        (initialSize - 4),
                        initialSize);
            byteArray  =
                ArrayUtils.subarray(byteArray, 0, 
                    (initialSize - 4));
            int expectedSize = 
                NumberUtils.intFromByteArray(encryptedMessageExpectedSizeBytes);

            // If expected and real sizes do not match, we will need to pad
            // (this happens because BigInteger removes 0x0's and -0x1's in
            // the leftmost side).
            if (byteArray.length != expectedSize) {

                // BigInteger can have removed, in the leftmost side:
                //      * 0x0's: for not being significative
                //      * -0x1's: for being translated as the "signum"
                int sizeDifference = 
                    (expectedSize - byteArray.length);

                byte[] padding = new byte[sizeDifference];
                for (int i = 0; i < sizeDifference; i++) {
                    padding[i] = (signum >= 0)? (byte)0x0 : (byte)-0x1;
                }
                    

                // Finally, the encrypted message bytes are represented
                // as they supposedly were when they were encrypted.
                    byteArray =
                    ArrayUtils.addAll(padding, byteArray);
                
            }
            
        }

        return byteArray;
        
    }
    
    
    private NumberUtils() {}
    
}
