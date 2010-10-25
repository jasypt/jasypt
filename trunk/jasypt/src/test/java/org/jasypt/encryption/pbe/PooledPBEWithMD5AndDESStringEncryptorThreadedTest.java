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
package org.jasypt.encryption.pbe;

import org.apache.commons.lang.time.StopWatch;




public class PooledPBEWithMD5AndDESStringEncryptorThreadedTest 
        extends AbstractPBEStringEncryptorThreadedTest {

    protected int poolSize = 2;
    
    
    public PooledPBEWithMD5AndDESStringEncryptorThreadedTest() {
        super();
    }
    
    public PooledPBEWithMD5AndDESStringEncryptorThreadedTest(final int numThreads, final int numIters, final int poolSize) {
        super(numThreads, numIters);
        this.poolSize = poolSize;
    }

    protected PBEStringEncryptor createEncryptor() {
        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
        encryptor.setPoolSize(poolSize);
        encryptor.setAlgorithm("PBEWithMD5AndDES");
        return encryptor;
    }
    
    
    public static void main(String[] args) {
        try {
            
            final int numThreads = Integer.valueOf(args[0]).intValue();
            final int numIters = Integer.valueOf(args[1]).intValue();
            final int poolSize = Integer.valueOf(args[2]).intValue();
            
            PooledPBEWithMD5AndDESStringEncryptorThreadedTest test = 
                new PooledPBEWithMD5AndDESStringEncryptorThreadedTest(numThreads, numIters, poolSize);
            
            System.out.println("Starting test. NumThreads: " + numThreads + " NumIters: " + numIters + " PoolSize: " + poolSize);
            StopWatch sw = new StopWatch();
            sw.start();
            test.testThreadedDigest();
            sw.stop();
            System.out.println("Test finished in: " + sw.toString());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    
}
