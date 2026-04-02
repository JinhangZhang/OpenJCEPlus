/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
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
@Fork(1)
public class TLSHandshakeBenchmark extends JMHBase {

    @Param({"X25519", "X25519MLKEM768"})
    public String namedGroup;

    @Param({"true", "false"})
    public boolean useCache;

    private static final String CIPHER_SUITE = "TLS_AES_256_GCM_SHA384";

    private SSLServerSocket serverSocket;
    private SSLSocketFactory clientFactory;
    private int port;
    private Thread serverThread;

    @Setup
    public void setup() throws Exception {
        super.setup("OpenJCEPlus");

        generateKeyStore();

        System.setProperty("javax.net.ssl.keyStore", "testkeys.p12");
        System.setProperty("javax.net.ssl.keyStorePassword", "password");
        System.setProperty("javax.net.ssl.trustStore", "testkeys.p12");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");

        SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        serverSocket = (SSLServerSocket) ssf.createServerSocket(0);

        serverSocket.setEnabledCipherSuites(new String[]{CIPHER_SUITE});
        
        port = serverSocket.getLocalPort();
        clientFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();

        serverThread = new Thread(() -> {
            while (!Thread.interrupted()) {
                try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                    socket.setEnabledProtocols(new String[]{"TLSv1.3"});
                    SSLParameters params = socket.getSSLParameters();
                    params.setNamedGroups(new String[]{namedGroup});
                    socket.setSSLParameters(params);
                    
                    socket.startHandshake();
                    socket.getInputStream().read();
                    
                } catch (IOException e) {
                    // socket closed or error occurred, exit thread
                }
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
    }

    @TearDown(Level.Trial)
    public void tearDown() throws Exception {
        if (serverThread != null) {
            serverThread.interrupt();
        }
        if (serverSocket != null) {
            serverSocket.close();
        }
    }

    @Benchmark
    public void testHandshake() throws Exception {
        try (SSLSocket clientSocket = (SSLSocket) clientFactory.createSocket("localhost", port)) {
            clientSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
            clientSocket.setEnabledCipherSuites(new String[]{CIPHER_SUITE});

            SSLParameters params = clientSocket.getSSLParameters();
            params.setNamedGroups(new String[]{namedGroup});
            clientSocket.setSSLParameters(params);

            clientSocket.startHandshake();

            clientSocket.getOutputStream().write(1);

            if (!useCache) {
                clientSocket.getSession().invalidate();
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
