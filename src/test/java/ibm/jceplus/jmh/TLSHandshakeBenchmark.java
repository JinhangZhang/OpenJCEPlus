/*
 * Copyright IBM Corp. 2026, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 10, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 4, time = 30, timeUnit = TimeUnit.SECONDS)
public class TLSHandshakeBenchmark extends JMHBase {

    private static final String PAYLOAD_1KB = "1024";

    @Param({"X25519", "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"})
    // @Param({"X25519MLKEM768"})
    public String namedGroup;

    @Param({"cached", "non-cached"})
    // @Param({"non-cached"})
    public String useCache;

    @Param({"TLS_AES_256_GCM_SHA384"})
    public String cipherSuite;

    @Param({PAYLOAD_1KB})
    public int payload;

    private SSLServerSocket serverSocket;
    private SSLContext sslContext;
    private SSLSocketFactory clientFactory;
    private int port;
    private Thread serverThread;
    private volatile boolean serverReady = false;
    private SSLSession cachedSession;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        super.setup("OpenJCEPlus");

        generateKeyStore();

        // Load keystore and truststore programmatically
        String keystorePath = "testkeys.p12";
        String keystorePassword = "password";
        
        // Load the keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            keyStore.load(fis, keystorePassword.toCharArray());
        }
        
        // Initialize KeyManagerFactory
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keystorePassword.toCharArray());
        
        // Initialize TrustManagerFactory
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        
        // Create SSLContext with the key and trust managers
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        
        SSLServerSocketFactory ssf = (SSLServerSocketFactory) sslContext.getServerSocketFactory();
        serverSocket = (SSLServerSocket) ssf.createServerSocket(0);

        serverSocket.setEnabledCipherSuites(new String[]{cipherSuite});
        serverSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
        
        port = serverSocket.getLocalPort();
        clientFactory = (SSLSocketFactory) sslContext.getSocketFactory();

        // Capture the current namedGroup and payload values for this trial
        final String currentNamedGroup = namedGroup;
        final int currentPayload = payload;
        
        serverThread = new Thread(() -> {
            while (!Thread.interrupted()) {
                try {
                    if (!serverReady) {
                        serverReady = true;
                    }
                    SSLSocket socket = (SSLSocket) serverSocket.accept();
                    socket.setEnabledProtocols(new String[]{"TLSv1.3"});
                    socket.setEnabledCipherSuites(new String[]{cipherSuite});
                    
                    // Set named groups if the method is available (Java 13+)
                    SSLParameters params = socket.getSSLParameters();
                    params.setNamedGroups(new String[]{currentNamedGroup});
                    socket.setSSLParameters(params);
                    
                    socket.startHandshake();
                    
                    // Read payload from client
                    if (currentPayload > 0) {
                        byte[] buffer = new byte[currentPayload];
                        int totalRead = 0;
                        while (totalRead < currentPayload) {
                            int read = socket.getInputStream().read(buffer, totalRead, currentPayload - totalRead);
                            if (read == -1) break;
                            totalRead += read;
                        }
                    } else {
                        socket.getInputStream().read();
                    }
                    
                    // Write payload back to client
                    if (currentPayload > 0) {
                        byte[] buffer = new byte[currentPayload];
                        socket.getOutputStream().write(buffer);
                    } else {
                        socket.getOutputStream().write(1);
                    }
                    socket.getOutputStream().flush();
                    socket.close();
                    
                } catch (IOException e) {
                    if (!Thread.interrupted() && !serverSocket.isClosed()) {
                        // Only log if not intentionally interrupted or socket closed
                        e.printStackTrace();
                    }
                    // Exit the loop if socket is closed
                    if (serverSocket.isClosed()) {
                        break;
                    }
                }
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
        
        // Wait for server to be ready
        while (!serverReady) {
            Thread.sleep(10);
        }
        // Give server a bit more time to fully initialize
        Thread.sleep(100);
    }

    @TearDown(Level.Trial)
    public void tearDown() throws Exception {
        // Interrupt the server thread first
        if (serverThread != null) {
            serverThread.interrupt();
        }
        
        // Then close the server socket to unblock accept()
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                // Ignore close exceptions during teardown
            }
        }
        
        // Wait for the server thread to finish
        if (serverThread != null) {
            try {
                serverThread.join(1000); // Wait up to 1 second for thread to finish
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    @Benchmark
    public void testHandshake() throws Exception {
        SSLSocket clientSocket = null;
        try {
            // Create a new socket for each handshake
            clientSocket = (SSLSocket) clientFactory.createSocket("localhost", port);
            clientSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
            clientSocket.setEnabledCipherSuites(new String[]{cipherSuite});

            SSLParameters params = clientSocket.getSSLParameters();
            params.setNamedGroups(new String[]{namedGroup});
            clientSocket.setSSLParameters(params);

            clientSocket.startHandshake();

            // Write payload to server
            if (payload > 0) {
                byte[] buffer = new byte[payload];
                clientSocket.getOutputStream().write(buffer);
            } else {
                clientSocket.getOutputStream().write(1);
            }
            clientSocket.getOutputStream().flush();
            
            // Read payload back from server
            // In TLS 1.3, the server sends NewSessionTicket after handshake completion.
            // Reading from the socket ensures we receive the NewSessionTicket before closing.
            // This is critical for session resumption to work properly.
            if (payload > 0) {
                byte[] buffer = new byte[payload];
                int totalRead = 0;
                while (totalRead < payload) {
                    int read = clientSocket.getInputStream().read(buffer, totalRead, payload - totalRead);
                    if (read == -1) break;
                    totalRead += read;
                }
            } else {
                clientSocket.getInputStream().read();
            }

            if ("cached".equals(useCache)) {
                // Cache the session for reuse in subsequent handshakes
                cachedSession = clientSocket.getSession();
            } else {
                // Invalidate the session to force full handshake
                clientSocket.getSession().invalidate();
            }
        } finally {
            if (clientSocket != null) {
                clientSocket.close();
            }
        }
    }

    private void generateKeyStore() throws Exception {
        File keystoreFile = new File("testkeys.p12");
        if (keystoreFile.exists()) {
            return; 
        }

        System.out.println("Generating testkeys keystore with EC...");
        ProcessBuilder processBuilder = new ProcessBuilder(
                "keytool",
                "-genkeypair",
                "-keyalg", "EC",
                "-keysize", "256",
                "-validity", "365",
                "-keystore", "testkeys.p12",
                "-storetype", "PKCS12",
                "-storepass", "password",
                "-keypass", "password",
                "-dname", "CN=localhost"
        );

        processBuilder.inheritIO();
        Process process = processBuilder.start();
        int exitCode = process.waitFor();

        if (exitCode != 0) {
            throw new RuntimeException("Failed to generate testkeys using keytool. Exit code: " + exitCode);
        }
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = TLSHandshakeBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
