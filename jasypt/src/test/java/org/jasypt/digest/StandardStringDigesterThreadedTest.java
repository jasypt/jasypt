package org.jasypt.digest;


import java.util.concurrent.atomic.AtomicInteger;

import junit.framework.TestCase;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.time.StopWatch;

// TODO: Remove watch and console output
public class StandardStringDigesterThreadedTest extends TestCase {

    
    public void testThreadedDigest() throws Exception {
        TesterLauncher launcher = new TesterLauncher();
        assertTrue(launcher.launch(100,1000) == 0);
    }
    
    
    private class TesterLauncher {

        private AtomicInteger runningThreads = null;
        private int numThreads = 0;
        
        public int launch(int numOfThreads, int numIters) throws Exception {
            
            this.numThreads = numOfThreads;
            
            StandardStringDigester digester = new StandardStringDigester();
            AtomicInteger errors = new AtomicInteger(0);
            runningThreads = new AtomicInteger(0);
            
            StopWatch watch = new StopWatch();
            watch.start();
            
            for (int i = 0; i < numOfThreads; i++) {
                TesterRunnable tester = 
                    new TesterRunnable(digester, numIters, errors, 
                            runningThreads, this);
                Thread testerThread = new Thread(tester);
                testerThread.start();
            }
            
            while (continueWaiting()) {
                synchronized (this) {
                    this.wait(numIters * 1000);
                }
            }
            
            watch.split();
            
            System.out.println("Threads: " + numOfThreads + " Iterations: " + numIters + " Errors: " + errors + " Time: " + watch.toSplitString());

            return errors.get();
            
        }
        
        private synchronized boolean continueWaiting() {
            return (runningThreads.get() < numThreads);
        }
        
    }
    
    
    private class TesterRunnable implements Runnable {

        private StandardStringDigester digester = null;
        private int numIters = 0;
        private String message = null;
        private AtomicInteger errors = null;
        private AtomicInteger finishedThreads = null;
        private TesterLauncher launcher = null;
        
        public TesterRunnable(StandardStringDigester digester, int numIters,  
                AtomicInteger errors, AtomicInteger finishedThreads,
                TesterLauncher launcher) {
            this.digester = digester;
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
                    String encryptedMessage = digester.digest(message);
                    if (!digester.matches(message, encryptedMessage)) {
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
