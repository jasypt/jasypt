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
package org.jasypt.exceptions;


/**
 * Exception thrown when an attempt is made to access the configured
 * password of an encryptor when this password has already been
 * cleaned (so that it appears no more as an immutable String in memory).
 * 
 * 
 * @since 1.8
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class PasswordAlreadyCleanedException extends RuntimeException {

    private static final long serialVersionUID = 7988484935273871733L;

    public PasswordAlreadyCleanedException() {
        super("Password already cleaned: The encryptor that uses this password has " +
                "already been initialized and therefore this password has been cleaned so "+
                "that it is no more present in memory. An exception has been raised when accessing " +
                "this property in order to avoid inconsistencies.");
    }

}
