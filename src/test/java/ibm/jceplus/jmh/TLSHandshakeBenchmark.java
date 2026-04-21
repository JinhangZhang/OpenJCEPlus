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
    private volatile boolean running = true;

    // --- Hardcoded Certificates (EC secp256r1) ---
    // 这些数据模拟了从 SSLContextTemplate 提取的标准测试证书
    private static final String CA_CERT_PEM = 
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBvjCCAWOgAwIBAgIJAIvFG6GbTroCMAoGCCqGSM49BAMCMDsxCzAJBgNVBAYT\n" +
        "AlVTMQ0wCwYDVQQKDARKYXZhMR0wGwYDVQQLDBRTdW5KU1NFIFRlc3QgU2VyaXZj\n" +
        "ZTAeFw0xODA1MjIwNzE4MTZaFw0zODA1MTcwNzE4MTZaMDsxCzAJBgNVBAYTAlVT\n" +
        "MQ0wCwYDVQQKDARKYXZhMR0wGwYDVQQLDBRTdW5KU1NFIFRlc3QgU2VyaXZjZTBZ\n" +
        "MBMGByqGSM49AgEGCCqGSM49AwEHA0IABBz1WeVb6gM2mh85z3QlvaB/l11b5h0v\n" +
        "LIzmkC3DKlVukZT+ltH2Eq1oEkpXuf7QmbM0ibrUgtjsWH3mULfmcWmjUDBOMB0G\n" +
        "A1UdDgQWBBRgz71z//oaMNKk7NNJcUbvGjWghjAfBgNVHSMEGDAWgBRgz71z//oa\n" +
        "MNKk7NNJcUbvGjWghjAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQCG\n" +
        "6wluh1r2/T6L31mZXRKf9JxeSf9pIzoLj+8xQeUChQIhAJ09wAi1kV8yePLh2FD9\n" +
        "2YEHlSQUAbwwqCDEVB5KxaqP\n" +
        "-----END CERTIFICATE-----";

    private static final String EE_CERT_STR = 
        "MIIBqjCCAVCgAwIBAgIJAPLY8qZjgNRAMAoGCCqGSM49BAMCMDsxCzAJBgNVBAYT\n" +
        "AlVTMQ0wCwYDVQQKDARKYXZhMR0wGwYDVQQLDBRTdW5KU1NFIFRlc3QgU2VyaXZj\n" +
        "ZTAeFw0xODA1MjIwNzE4MTZaFw0zODA1MTcwNzE4MTZaMFUxCzAJBgNVBAYTAlVT\n" +
        "MQ0wCwYDVQQKDARKYXZhMR0wGwYDVQQLDBRTdW5KU1NFIFRlc3QgU2VyaXZjZTEY\n" +
        "MBYGA1UEAwwPUmVncmVzc2lvbiBUZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n" +
        "QgAEb+9n05qfXnfHUb0xtQJNS4JeSi6IjOfW5NqchvKnfJey9VkJzR7QHLuOESdf\n" +
        "xlR7q8YIWgih3iWLGfB+wxHiOqMjMCEwHwYDVR0jBBgwFoAUYM+9c//6GjDSpOzT\n" +
        "SXFG7xo1oIYwCgYIKoZIzj0EAwIDSAAwRQIgWpRegWXMheiD3qFdd8kMdrkLxRbq\n" +
        "1zj8nQMEwFTUjjQCIQDRIrAjZX+YXHN9b0SoWWLPUq0HmiFIi8RwMnO//wJIGQ==";

    private static final String EE_PRIV_KEY_STR = 
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgn5K03bpTLjEtFQRa\n" +
        "JUtx22gtmGEvvSUSQdimhGthdtihRANCAARv72fTmp9ed8dRvTG1Ak1Lgl5KLoiM\n" +
        "59bk2pyG8qd8l7L1WQnNHtAcu44RJ1/GVHurxghaCKHeJYsZ8H7DEeI6";

    @Setup(Level.Trial)
    public void setup() throws Exception {
        super.setup("OpenJCEPlus");

        // 1. 初始化内存 KeyStore
        char[] password = "password".toCharArray();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate caCert = cf.generateCertificate(new ByteArrayInputStream(CA_CERT_PEM.getBytes()));
        Certificate eeCert = cf.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(EE_CERT_STR)));
        
        KeyFactory kf = KeyFactory.getInstance("EC");
        PrivateKey eeKey = kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(EE_PRIV_KEY_STR.replace("\n", ""))));

        // 设置证书链和私钥
        ks.setCertificateEntry("ca", caCert);
        ks.setKeyEntry("ee", eeKey, password, new Certificate[]{eeCert});

        // 2. 初始化 SSLContext
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, password);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        // 如果是 non-cached 模式，关闭上下文缓存
        if ("non-cached".equals(useCache)) {
            sslContext.getClientSessionContext().setSessionCacheSize(0);
            sslContext.getServerSessionContext().setSessionCacheSize(0);
        }

        // 3. 建立 ServerSocket
        SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
        serverSocket = (SSLServerSocket) ssf.createServerSocket(0, 50, InetAddress.getLoopbackAddress());
        serverSocket.setEnabledCipherSuites(new String[]{cipherSuite});
        serverSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
        port = serverSocket.getLocalPort();
        
        clientFactory = sslContext.getSocketFactory();

        final String currentNamedGroup = namedGroup;
        final int currentPayload = payload;

        serverThread = new Thread(() -> {
            while (running && !Thread.interrupted()) {
                serverReady = true;
                try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                    socket.setEnabledProtocols(new String[]{"TLSv1.3"});
                    socket.setEnabledCipherSuites(new String[]{cipherSuite});
                    
                    SSLParameters params = socket.getSSLParameters();
                    params.setNamedGroups(new String[]{currentNamedGroup});
                    socket.setSSLParameters(params);
                    
                    socket.startHandshake();
                    
                    byte[] buffer = new byte[currentPayload];
                    socket.getInputStream().read(buffer);
                    socket.getOutputStream().write(buffer);
                    socket.getOutputStream().flush();
                } catch (IOException e) {
                    if (running) e.printStackTrace();
                }
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();

        while (!serverReady) { 
            Thread.sleep(10); 
        }
    }

    @Benchmark
    public void testHandshake() throws Exception {
        try (SSLSocket clientSocket = (SSLSocket) clientFactory.createSocket(InetAddress.getLoopbackAddress(), port)) {
            clientSocket.setEnabledProtocols(new String[]{"TLSv1.3"});
            clientSocket.setEnabledCipherSuites(new String[]{cipherSuite});

            SSLParameters params = clientSocket.getSSLParameters();
            params.setNamedGroups(new String[]{namedGroup});
            clientSocket.setSSLParameters(params);

            clientSocket.startHandshake();

            // Payload 读写
            byte[] buffer = new byte[payload];
            clientSocket.getOutputStream().write(buffer);
            clientSocket.getOutputStream().flush();
            
            int totalRead = 0;
            while (totalRead < payload) {
                int read = clientSocket.getInputStream().read(buffer, totalRead, payload - totalRead);
                if (read == -1) break;
                totalRead += read;
            }

            if ("non-cached".equals(useCache)) {
                clientSocket.getSession().invalidate();
            }
        }
    }

    @TearDown(Level.Trial)
    public void tearDown() throws Exception {
        running = false;
        if (serverSocket != null) serverSocket.close();
        if (serverThread != null) {
            serverThread.interrupt();
            serverThread.join(1000);
        }
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = TLSHandshakeBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);
        new Runner(opt).run();
    }
}
