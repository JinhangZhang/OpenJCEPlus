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

    @Param({"X25519", "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"})
    public String namedGroup;

    @Param({"cached", "non-cached"})
    public String useCache;

    @Param({"TLS_AES_256_GCM_SHA384"})
    public String cipherSuite;

    @Param({"1024"})
    public int payload;

    private SSLServerSocket serverSocket;
    private SSLContext sslContext;
    private SSLSocketFactory clientFactory;
    private int port;
    private Thread serverThread;
    private volatile boolean serverReady = false;
    private volatile boolean running = true;

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

        char[] pwd = "passphrase".toCharArray();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate ca = cf.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(CA_CERT_B64)));
        Certificate ee = cf.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(EE_CERT_B64)));
        PrivateKey key = KeyFactory.getInstance("EC").generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(EE_KEY_B64)));

        ks.setCertificateEntry("ca", ca);
        ks.setKeyEntry("ee", key, pwd, new Certificate[]{ee});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
        kmf.init(ks, pwd);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(ks);

        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        if ("non-cached".equals(useCache)) {
            sslContext.getClientSessionContext().setSessionCacheSize(0);
            sslContext.getServerSessionContext().setSessionCacheSize(0);
        } else {
            sslContext.getClientSessionContext().setSessionCacheSize(100);
            sslContext.getServerSessionContext().setSessionCacheSize(100);
        }

        SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
        serverSocket = (SSLServerSocket) ssf.createServerSocket(0, 50, InetAddress.getLoopbackAddress());
        port = serverSocket.getLocalPort();
        clientFactory = sslContext.getSocketFactory();

        startServer();

        if ("cached".equals(useCache)) {
            warmupSession();
        }
    }

    private void startServer() {
        serverThread = new Thread(() -> {
            while (running && !Thread.interrupted()) {
                serverReady = true;
                try (SSLSocket s = (SSLSocket) serverSocket.accept()) {
                    s.setEnabledProtocols(new String[]{"TLSv1.3"});
                    s.setEnabledCipherSuites(new String[]{cipherSuite});
                    SSLParameters p = s.getSSLParameters();
                    p.setNamedGroups(new String[]{namedGroup});
                    s.setSSLParameters(p);
                    s.startHandshake();
                    byte[] b = new byte[payload];
                    int r = s.getInputStream().read(b);
                    if (r != -1) {
                        s.getOutputStream().write(b, 0, r);
                        s.getOutputStream().flush();
                    }
                } catch (IOException e) {
                    if (running) {
                        // Expected during teardown
                    }
                }
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
        while (!serverReady) {
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void warmupSession() throws Exception {
        try (SSLSocket s = (SSLSocket) clientFactory.createSocket(InetAddress.getLoopbackAddress(), port)) {
            s.setEnabledProtocols(new String[]{"TLSv1.3"});
            SSLParameters p = s.getSSLParameters();
            p.setNamedGroups(new String[]{namedGroup});
            s.setSSLParameters(p);
            s.startHandshake();
            // 在 TLS 1.3 中，握手完成后必须发包并收包，
            // 才能确保收到异步发送的 NewSessionTicket
            s.getOutputStream().write(1);
            s.getInputStream().read();
        }
    }

    @Benchmark
    public void testHandshake() throws Exception {
        try (SSLSocket s = (SSLSocket) clientFactory.createSocket(InetAddress.getLoopbackAddress(), port)) {
            s.setEnabledProtocols(new String[]{"TLSv1.3"});
            s.setEnabledCipherSuites(new String[]{cipherSuite});
            SSLParameters p = s.getSSLParameters();
            p.setNamedGroups(new String[]{namedGroup});
            s.setSSLParameters(p);

            s.startHandshake();

            byte[] w = new byte[payload];
            s.getOutputStream().write(w);
            s.getOutputStream().flush();
            byte[] r = new byte[payload];
            int total = 0;
            while (total < payload) {
                int read = s.getInputStream().read(r, total, payload - total);
                if (read == -1) {
                    break;
                }
                total += read;
            }

            if ("non-cached".equals(useCache)) {
                s.getSession().invalidate();
            }
        }
    }

    @TearDown(Level.Trial)
    public void tearDown() throws Exception {
        running = false;
        if (serverSocket != null) {
            serverSocket.close();
        }
        if (serverThread != null) {
            serverThread.interrupt();
            serverThread.join(1000);
        }
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = optionsBuild(TLSHandshakeBenchmark.class.getSimpleName(),
                TLSHandshakeBenchmark.class.getSimpleName());
        new Runner(opt).run();
    }
}
