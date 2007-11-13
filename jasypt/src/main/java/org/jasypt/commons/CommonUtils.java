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
package org.jasypt.commons;

import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang.BooleanUtils;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

/**
 * <p>
 * Common utils regarding treatment of parameter values and encoding operations.
 * <b>This class is for internal use only</b>. 
 * </p> 
 * 
 * @since 1.3
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public class CommonUtils {

    public static final String STRING_OUTPUT_TYPE_BASE64 = "base64"; 
    public static final String STRING_OUTPUT_TYPE_HEXADECIMAL = "hexadecimal"; 
    
    private static final List STRING_OUTPUT_TYPE_HEXADECIMAL_NAMES =
        Arrays.asList(
            new String[] {
                "HEXADECIMAL", "HEXA", "0X", "HEX", "HEXADEC"
            }
        );
    
    private static char[] hexDigits = 
        {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    
    
    
    public static Boolean getStandardBooleanValue(String valueStr) {
        return BooleanUtils.toBooleanObject(valueStr);
    }
    
    
    public static String getStandardStringOutputType(String valueStr) {
        if (valueStr == null) {
            return null;
        }
        if (STRING_OUTPUT_TYPE_HEXADECIMAL_NAMES.contains(valueStr.toUpperCase())) {
            return STRING_OUTPUT_TYPE_HEXADECIMAL;
        }
        return STRING_OUTPUT_TYPE_BASE64;
    }

    
    public static String toHexadecimal(byte[] message) {
        if (message == null) {
            return null;
        }
        StringBuffer buffer = new StringBuffer();
        for (int i = 0; i < message.length; i++) {
            int curByte = message[i] & 0xff;
            buffer.append(hexDigits[(curByte >> 4)]);
            buffer.append(hexDigits[curByte & 0xf]);
        }
        return buffer.toString();
    }
    
    
    public static byte[] fromHexadecimal(String message) {
        if (message == null) {
            return null;
        }
        if ((message.length() % 2) != 0) {
            throw new EncryptionOperationNotPossibleException();
        }
        try {
            byte[] result = new byte[message.length() / 2];
            for (int i = 0; i < message.length(); i = i + 2) {
                int first = Integer.parseInt("" + message.charAt(i), 16);
                int second = Integer.parseInt("" + message.charAt(i + 1), 16);
                result[i/2] = (byte) (0x0 + ((first & 0xff) << 4) + (second & 0xff));
            }
            return result;
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }
    }
    
    
    // This class should only be called statically
    private CommonUtils() {
        super();
    }
    
}
