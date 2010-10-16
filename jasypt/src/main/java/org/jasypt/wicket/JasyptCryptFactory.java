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
package org.jasypt.wicket;

import org.apache.wicket.util.crypt.ICrypt;
import org.apache.wicket.util.crypt.ICryptFactory;
import org.jasypt.encryption.pbe.PBEByteEncryptor;
import org.jasypt.encryption.pbe.PBEStringEncryptor;


/**
 * <p>
 * Implementation of the Apache Wicket {@link ICryptFactory} interface
 * which returns {@link JasyptCrypt} instances.
 * </p>
 * <p>
 * Requires a {@link PBEByteEncryptor} as a constructor argument, which can
 * be created or retrieved from any part of the jasypt encryption configuration 
 * infrastructure.
 * </p>
 * <p>
 * 
 * </p>
 * <p>
 * This class is <i>thread-safe</i>.
 * </p>
 * 
 * @since 1.4
 * @author Daniel Fern&aacute;ndez
 *
 */
public final class JasyptCryptFactory implements ICryptFactory {

    // Encryptor doesn't need to be instanced each time. We hold a reference.
    private final JasyptCrypt jasyptCrypt;
    
    /**
     * <p>
     * Creates a new instance of <tt>JasyptCryptFactory</tt>.
     * </p>
     * <p>
     * This factory uses an instance of {@link PBEByteEncryptor} instead of
     * a {@link PBEStringEncryptor} (as could be expected) because Wicket
     * requires a specific type of String encoding (<i>URL and file safe
     * BASE64</i>), which is managed by a wicket internal class, and which
     * expectes byte[] input.
     * </p>
     * 
     * @param encryptor the PBEByteEncryptor to be used.
     */
    public JasyptCryptFactory(final PBEByteEncryptor encryptor) {
        this.jasyptCrypt = new JasyptCrypt(encryptor);
    }

    
    /**
     * <p>
     * Return a new encryptor object.
     * </p>
     * <p>
     * This method returns always the same <tt>JasyptCrypt</tt> object, instead
     * of creating a new one.
     * </p>
     */
    public ICrypt newCrypt() {
        return this.jasyptCrypt;
    }


}
