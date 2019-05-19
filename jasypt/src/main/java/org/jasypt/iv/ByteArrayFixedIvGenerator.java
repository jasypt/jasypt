/*
 * =============================================================================
 * 
 *   Copyright (c) 2019, The JASYPT team (http://www.jasypt.org)
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
package org.jasypt.iv;

import org.jasypt.commons.CommonUtils;
import org.jasypt.exceptions.EncryptionInitializationException;

/**
 * <p>
 * Byte-array based implementation of {@link FixedIvGenerator}, that will
 * always return the same initialization vector (IV).
 * </p>
 * <p>
 * If the requested IV has a size in bytes smaller than the specified IV,
 * the first n bytes are returned. If it is larger, an exception is thrown.
 * </p>
 * <p>
 * This class is <i>thread-safe</i>.
 * </p>
 * 
 * @since 1.9.3
 * 
 * @author Hoki Torres
 * 
 */
public class ByteArrayFixedIvGenerator implements FixedIvGenerator {

    private final byte[] iv;

    /**
     * Creates a new instance of <tt>FixedByteArrayIvGenerator</tt>
     *
     * @param iv the specified iv.
     */
    public ByteArrayFixedIvGenerator(final byte[] iv) {
        super();
        CommonUtils.validateNotNull(iv, "Initialization vector cannot be set null");
        this.iv = (byte[]) iv.clone();
    }

    
    /**
     * Return iv with the specified byte length.
     * 
     * @param lengthBytes length in bytes.
     * @return the generated iv.
     */
    public byte[] generateIv(final int lengthBytes) {
        if (this.iv.length < lengthBytes) {
            throw new EncryptionInitializationException(
                    "Requested initialization vector larger than set");
        }
        final byte[] generatedIv = new byte[lengthBytes];
        System.arraycopy(this.iv, 0, generatedIv, 0, lengthBytes);
        return generatedIv;
    }


    /**
     * As this iv generator provides a fixed iv, its inclusion
     * unencrypted in encryption results
     * is not necessary, and in fact not desirable (so that it remains hidden).
     * 
     * @return false
     */
    public boolean includePlainIvInEncryptionResults() {
        return false;
    }

    
}
