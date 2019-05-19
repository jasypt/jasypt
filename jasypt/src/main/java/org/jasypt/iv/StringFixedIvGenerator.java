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

import java.io.UnsupportedEncodingException;

/**
 * <p>
 * String based implementation of {@link IvGenerator}, that will
 * always return the same initialization vector (IV). This IV is returned as bytes using the
 * specified charset for conversion (UTF-8 by default).
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
public class StringFixedIvGenerator implements FixedIvGenerator {

    private static final String DEFAULT_CHARSET = "UTF-8";

    private final String iv;
    private final String charset;
    private final byte[] ivBytes;



    /**
     * Creates a new instance of <tt>StringFixedIvGenerator</tt> using
     * the default charset.
     *
     * @param iv the specified IV.
     */
    public StringFixedIvGenerator(final String iv) {
        this(iv, null);
    }


    /**
     * Creates a new instance of <tt>StringFixedIvGenerator</tt>
     *
     * @param iv the specified IV.
     * @param charset the specified charset
     */
    public StringFixedIvGenerator(final String iv, final String charset) {
        super();
        CommonUtils.validateNotNull(iv, "IV cannot be set null");
        this.iv = iv;
        this.charset = (charset != null? charset : DEFAULT_CHARSET);
        try {
            this.ivBytes = this.iv.getBytes(this.charset);
        } catch (UnsupportedEncodingException e) {
            throw new EncryptionInitializationException(
                "Invalid charset specified: " + this.charset);
        }
    }

    
    /**
     * Return IV with the specified byte length.
     * 
     * @param lengthBytes length in bytes.
     * @return the generated IV.
     */
    public byte[] generateIv(final int lengthBytes) {
        if (this.ivBytes.length < lengthBytes) {
            throw new EncryptionInitializationException(
                    "Requested IV larger than set");
        }
        final byte[] generatedIv = new byte[lengthBytes];
        System.arraycopy(this.ivBytes, 0, generatedIv, 0, lengthBytes);
        return generatedIv;
    }


    /**
     * As this IV generator provides a fixed IV, its inclusion
     * unencrypted in encryption results
     * is not necessary, and in fact not desirable (so that it remains hidden).
     * 
     * @return false
     */
    public boolean includePlainIvInEncryptionResults() {
        return false;
    }

    
}
