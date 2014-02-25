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
package org.jasypt.salt;

import org.jasypt.commons.CommonUtils;
import org.jasypt.exceptions.EncryptionInitializationException;

/**
 * <p>
 * Byte-array based implementation of {@link FixedSaltGenerator}, that will
 * always return the same salt.
 * </p>
 * <p>
 * If the requested salt has a size in bytes smaller than the specified salt, 
 * the first n bytes are returned. If it is larger, an exception is thrown.
 * </p>
 * <p>
 * This class is <i>thread-safe</i>.
 * </p>
 * 
 * @since 1.9.2
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public class ByteArrayFixedSaltGenerator implements FixedSaltGenerator {

    private final byte[] salt;
    
    /**
     * Creates a new instance of <tt>FixedByteArraySaltGenerator</tt>
     *
     * @param salt the specified salt.
     */
    public ByteArrayFixedSaltGenerator(final byte[] salt) {
        super();
        CommonUtils.validateNotNull(salt, "Salt cannot be set null");
        this.salt = (byte[]) salt.clone();
    }

    
    /**
     * Return salt with the specified byte length.
     * 
     * @param lengthBytes length in bytes.
     * @return the generated salt. 
     */
    public byte[] generateSalt(final int lengthBytes) {
        if (this.salt.length < lengthBytes) {
            throw new EncryptionInitializationException(
                    "Requested salt larger than set");
        }
        final byte[] generatedSalt = new byte[lengthBytes];
        System.arraycopy(this.salt, 0, generatedSalt, 0, lengthBytes);
        return generatedSalt;
    }


    /**
     * As this salt generator provides a fixed salt, its inclusion 
     * unencrypted in encryption results
     * is not necessary, and in fact not desirable (so that it remains hidden).
     * 
     * @return false
     */
    public boolean includePlainSaltInEncryptionResults() {
        return false;
    }

    
}
