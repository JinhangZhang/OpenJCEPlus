/*
 * Copyright IBM Corp. 2026, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
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
    public String namedGroup;

    @Param({"cached", "non-cached"})
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

    // --- Hardcoded 证书数据 (EC secp256r1) ---
    private static final String CA_CERT_B64 = 
            "MIIBvjCCAWOgAwIBAgIJAIvFG6GbTroCMAoGCCqGSM49BAMCMDsxCzAJBgNVBAYT" +
            "AlVTMQ0wCwYDVQQKDARKYXZhMR0wGwYDVQQLDBRTdW5KU1NFIFRlc3QgU2VyaXZj" +
            "ZTAeFw0xODA1MjIwNzE4MTZaFw0zODA1MTcwNzE4MTZaMDsxCzAJBgNVBAYTAlVT" +
            "MQ0wCwYDVQQKDARKYXZhMR0wGwYDVQQLDBRTdW5KU1NFIFRlc3QgU2VyaXZjZTBZ" +
            "MBMGByqGSM49AgEGCCqGSM49AwEHA0IABBz1WeVb6gM2mh85z3QlvaB/l11b5h0v" +
            "LIzmkC3DKlVukZT+ltH2Eq1oEkpXuf7QmbM0ibrUgtjsWH3mULfmcWmjUDBOMB0G" +
            "A1UdDgQWBBRgz71z//oaMNKk7NNJcUbvGjWghjAfBgNVHSMEGDAWgBRgz71z//oa" +
            "MNKk7NNJcUbvGjWghjAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQCG" +
            "6wluh1r2/T6L31mZXRKf9JxeSf9pIzoLj+8xQeUChQIhAJ09wAi1kV8yePLh2FD9" +
            "2YEHlSQUAbwwqCDEVB5KxaqP";

    private static final String EE_CERT_B64 = 
            "MIIBqjCCAVCgAwIBAgIJAPLY8qZjgNRAMAoGCCqGSM49BAMCMDsxCzAJBgNVBAYT" +
            "AlVTMQ0wCwYDVQQKDARKYXZhMR0wGwYDVQQLDBRTdW5KU1NFIFRlc3QgU2VyaXZj" +
            "ZTAeFw0xODA1MjIwNzE4MTZaFw0zODA1MTcwNzE4MTZaMFUxCzAJBgNVBAYTAlVT" +
            "MQ0wCwYDVQQKDARKYXZhMR0wGwYDVQQLDBRTdW5KU1NFIFRlc3QgU2VyaXZjZTEY" +
            "MBYGA1UEAwwPUmVncmVzc2lvbiBUZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD" +
            "QgAEb+9n05qfXnfHUb0xtQJNS4JeSi6IjOfW5NqchvKnfJey9VkJzR7QHLuOESdf" +
            "xlR7q8YIWgih3iWLGfB+wxHiOqMjMCEwHwYDVR0jBBgwFoAUYM+9c//6GjDSpOzT" +
            "SXFG7xo1oIYwCgYIKoZIzj0EAwIDSAAwRQIgWpRegWXMheiD3qFdd8kMdrkLxRbq" +
            "1zj8nQMEwFTUjjQCIQDRIrAjZX+YXHN9b0SoWWLPUq0HmiFIi8RwMnO//wJIGQ==";

    private static final String EE_KEY_B64 = 
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgn5K03bpTLjEtFQRa" +
            "JUtx22gtmGEvvSUSQdimhGthdtihRANCAARv72fTmp9ed8dRvTG1Ak1Lgl5KLoiM" +
            "59bk2pyG8qd8l7L1WQnNHtAcu44RJ1/GVHurxghaCKHeJYsZ8H7DEeI6";

    @Setup(Level.Trial)
    public void setup() throws Exception {
        super.setup("OpenJCEPlus");
        Security.setProperty("jdk.tls.disabledAlgorithms", "");

        // 替换 generateKeyStore()：直接在内存构建 KeyStore
        String keystorePassword = "password";
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate caCert = cf.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(CA_CERT_B64)));
        Certificate eeCert = cf.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(EE_CERT_B64)));
        PrivateKey eePrivKey = KeyFactory.getInstance("EC").generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(EE_KEY_B64)));

        keyStore.setCertificateEntry("ca", caCert);
        keyStore.setKeyEntry("ee", eePrivKey, keystorePassword.toCharArray(), new Certificate[]{eeCert});

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
        serverSocket = (SSLServerSocket) ssf.createServerSocket(0, 50, InetAddress.getLoopbackAddress());

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
                        e.printStackTrace();
                    }
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
        if (serverThread != null) {
            serverThread.interrupt();
        }
        
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                // Ignore
            }
        }
        
        if (serverThread != null) {
            try {
                serverThread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    @Benchmark
    public void testHandshake() throws Exception {
        SSLSocket clientSocket = null;
        try {
            clientSocket = (SSLSocket) clientFactory.createSocket(InetAddress.getLoopbackAddress(), port);
            clientSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
            clientSocket.setEnabledCipherSuites(new String[]{cipherSuite});

            SSLParameters params = clientSocket.getSSLParameters();
            params.setNamedGroups(new String[]{namedGroup});
            clientSocket.setSSLParameters(params);

            clientSocket.startHandshake();

            if (payload > 0) {
                byte[] buffer = new byte[payload];
                clientSocket.getOutputStream().write(buffer);
            } else {
                clientSocket.getOutputStream().write(1);
            }
            clientSocket.getOutputStream().flush();
            
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
                cachedSession = clientSocket.getSession();
            } else {
                clientSocket.getSession().invalidate();
            }
        } finally {
            if (clientSocket != null) {
                clientSocket.close();
            }
        }
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = TLSHandshakeBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);
        new Runner(opt).run();
    }
}
