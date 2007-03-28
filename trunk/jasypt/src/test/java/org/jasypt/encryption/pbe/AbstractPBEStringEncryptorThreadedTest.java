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


import java.util.concurrent.atomic.AtomicInteger;

import junit.framework.TestCase;

import org.apache.commons.lang.RandomStringUtils;

public abstract class AbstractPBEStringEncryptorThreadedTest extends TestCase {

    
    public void testThreadedDigest() throws Exception {
        TesterLauncher launcher = new TesterLauncher();
        assertTrue(launcher.launch(10,100) == 0);
    }
    
    protected abstract PBEStringEncryptor createEncryptor();
    
    private class TesterLauncher {

        private AtomicInteger runningThreads = null;
        private int numThreads = 0;
        
        public int launch(int numOfThreads, int numIters) throws Exception {
            
            this.numThreads = numOfThreads;
            
            PBEStringEncryptor encryptor = createEncryptor();
            
            String password = "A_PASSWORD";
            encryptor.setPassword(password);
            
            AtomicInteger errors = new AtomicInteger(0);
            runningThreads = new AtomicInteger(0);
            
            for (int i = 0; i < numOfThreads; i++) {
                TesterRunnable tester = 
                    new TesterRunnable(encryptor, numIters, errors, 
                            runningThreads, this);
                Thread testerThread = new Thread(tester);
                testerThread.start();
            }
            
            while (continueWaiting()) {
                synchronized (this) {
                    this.wait(numIters * 1000);
                }
            }

            return errors.get();
            
        }
        
        private synchronized boolean continueWaiting() {
            return (runningThreads.get() < numThreads);
        }
        
    }
    
    
    private class TesterRunnable implements Runnable {

        private PBEStringEncryptor encryptor = null;
        private int numIters = 0;
        private String message = null;
        private AtomicInteger errors = null;
        private AtomicInteger finishedThreads = null;
        private TesterLauncher launcher = null;
        
        public TesterRunnable(PBEStringEncryptor encryptor, int numIters,  
                AtomicInteger errors, AtomicInteger finishedThreads,
                TesterLauncher launcher) {
            this.encryptor = encryptor;
            this.numIters = numIters;
            this.message = RandomStringUtils.randomAscii(20);
            this.errors = errors;
            this.finishedThreads = finishedThreads;
            this.launcher = launcher;
        }
        
        public void run() {
            
            int localErrors = 0;
            for (int i = 0; i < numIters; i++) {
                try {
                    String encryptedMessage = encryptor.encrypt(message);
                    if (!message.equals(encryptor.decrypt(encryptedMessage))) {
                        localErrors++;
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    localErrors++;
                }
            }

            synchronized (launcher) {
                if (localErrors > 0) {
                    errors.addAndGet(localErrors);
                }
                finishedThreads.incrementAndGet();
                launcher.notify();
            }
        }
        
        
    }
    
}
