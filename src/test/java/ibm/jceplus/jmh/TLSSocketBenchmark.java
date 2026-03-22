/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Thread)
public class TLSSocketBenchmark extends JMHBase {

    @Param({
        "SunJCE:x25519mlkem768",
        "OpenJCEPlus:x25519mlkem768",
        "OpenJCEPlus:x25519"
    })
    private String config;
    private SSLContext clientContext;
    private SSLContext serverContext;
    private SSLServerSocket serverSocket;
    private int port;
    private volatile boolean running = true;
    private Thread serverThread;

    @Setup
    public void setup() throws Exception {
        String[] parts = config.split(":");
        String providerName = parts[0];
        String groupName = parts[1];

        System.setProperty("jdk.tls.namedGroups", groupName);

        insertProvider(providerName);

        serverContext = SSLContext.getInstance("TLSv1.3", "SunJSSE");
        serverContext.init(getKeyManagers(), null, null);
        serverContext.getServerSessionContext().setSessionCacheSize(0);

        SSLServerSocketFactory ssf = serverContext.getServerSocketFactory();
        serverSocket = (SSLServerSocket) ssf.createServerSocket(0);
        port = serverSocket.getLocalPort();

        serverThread = new Thread(() -> {
            while (running) {
                try (SSLSocket s = (SSLSocket) serverSocket.accept()) {
                    s.startHandshake();
                } catch (IOException e) {
                    if (running) {
                        System.err.println("Server Accept Error: " + e.getMessage());
                    }
                }
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();

        clientContext = SSLContext.getInstance("TLSv1.3", "SunJSSE");
        clientContext.init(null, getTrustManagers(), null);
        clientContext.getClientSessionContext().setSessionCacheSize(0);
    }

    @Benchmark
    public void testFullHandshake() throws Exception {
        SSLSocketFactory sf = clientContext.getSocketFactory();
        try (SSLSocket clientSocket = (SSLSocket) sf.createSocket(InetAddress.getLoopbackAddress(), port)) {
            SSLParameters params = clientSocket.getSSLParameters();
            params.setProtocols(new String[] {"TLSv1.3"});
            clientSocket.setSSLParameters(params);

            clientSocket.startHandshake();
        }
    }

    @TearDown(Level.Trial)
    public void tearDown() throws Exception {
        running = false;
        if (serverSocket != null) {
            serverSocket.close();
        }
        if (serverThread != null) {
            serverThread.join(500);
        }
    }

    private KeyManager[] getKeyManagers() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = getClass().getResourceAsStream("/test-keystore.p12")) {
            ks.load(is, "password".toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "password".toCharArray());
        return kmf.getKeyManagers();
    }

    private TrustManager[] getTrustManagers() {
        return new TrustManager[] {
            new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] x, String s) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] x, String s) {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
            }
        };
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = TLSSocketBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}
