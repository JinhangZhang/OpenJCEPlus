/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetAddress;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.runner.options.Options;

/**
 * 继承 JMHBase 以复用 IBM 环境配置。
 * 测试重点：比较 SunJCE 和 OpenJCEPlus 在 TLS 1.3 PQC 混合模式下的握手效率。
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Thread)
public class TLSSocketBenchmark extends JMHBase {

    @Param({
        "SunJCE:x25519_mlkem768", 
        "OpenJCEPlus:x25519_mlkem768", 
        "OpenJCEPlus:x25519"
    })
    private String config;

    private SSLContext clientContext;
    private SSLContext serverContext;
    private SSLServerSocket serverSocket;
    private int port;
    private volatile boolean running = true;
    private Thread serverThread;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        String[] parts = config.split(":");
        String providerName = parts[0];
        String groupName = parts[1];

        // --- 关键点 1：全局锁定命名组 ---
        // 由于 SSLParameters 缺少 setNamedGroups，我们通过系统属性强制 TLS 1.3 使用特定算法
        // 这确保了 ClientHello 会直接发送该组的 KeyShare，避免 HelloRetryRequest
        System.setProperty("jdk.tls.namedGroups", groupName);

        // --- 关键点 2：插入指定的 Provider ---
        super.insertProvider(providerName);

        // --- 关键点 3：初始化服务端 ---
        serverContext = SSLContext.getInstance("TLSv1.3", providerName);
        // 使用内置 Helper 获取测试证书（见下文）
        serverContext.init(getKeyManagers(), null, null);
        serverContext.getServerSessionContext().setSessionCacheSize(0); // 禁用重用

        serverSocket = (SSLServerSocket) serverContext.getServerSocketFactory().createServerSocket(0);
        port = serverSocket.getLocalPort();

        // 启动后台 Server 监听线程
        serverThread = new Thread(() -> {
            while (running) {
                try (SSLSocket s = (SSLSocket) serverSocket.accept()) {
                    s.startHandshake(); // 执行服务端 PQC Wrap (Encapsulate)
                } catch (IOException e) {
                    if (running) System.err.println("Server Accept Error: " + e.getMessage());
                }
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();

        // --- 关键点 4：初始化客户端 ---
        clientContext = SSLContext.getInstance("TLSv1.3", providerName);
        clientContext.init(null, getTrustManagers(), null);
        clientContext.getClientSessionContext().setSessionCacheSize(0); // 禁用重用
    }

    @Benchmark
    public void testFullHandshake() throws Exception {
        // 由于已经在 Setup 中通过 System Property 锁定了算法，
        // 这里的代码可以保持极其精简，专注于测量握手耗时。
        try (SSLSocket clientSocket = (SSLSocket) clientContext.getSocketFactory()
                .createSocket(InetAddress.getLoopbackAddress(), port)) {
            
            SSLParameters params = clientSocket.getSSLParameters();
            params.setProtocols(new String[]{"TLSv1.3"});
            clientSocket.setSSLParameters(params);

            // 触发握手：Client 发送 PQC KeyShare -> Server 执行 Wrap -> Client 执行 Unwrap
            clientSocket.startHandshake();
        }
    }

    @TearDown(Level.Trial)
    public void tearDown() throws Exception {
        running = false;
        if (serverSocket != null) serverSocket.close();
        if (serverThread != null) serverThread.join(500);
    }

    // --- Helper Methods ---

    private KeyManager[] getKeyManagers() throws Exception {
        // 建议在生产环境中从 jks 文件加载。此处演示通过 KeyStore 载入。
        // 你需要确保你的测试资源目录下有一个 test-keystore.jks
        KeyStore ks = KeyStore.getInstance("JKS");
        try (java.io.InputStream is = getClass().getResourceAsStream("/test-keystore.jks")) {
            if (is == null) {
                throw new RuntimeException("Missing test-keystore.jks in resources!");
            }
            ks.load(is, "password".toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "password".toCharArray());
        return kmf.getKeyManagers();
    }

    private TrustManager[] getTrustManagers() {
        // 信任所有证书，以确保 Benchmark 压力点在 Key Exchange 而非证书校验
        return new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] x, String s) {}
            public void checkServerTrusted(X509Certificate[] x, String s) {}
            public X509Certificate[] getAcceptedIssuers() { return null; }
        }};
    }

    public static void main(String[] args) throws RunnerException {
        String testSimpleName = TLSSocketBenchmark.class.getSimpleName();
        Options opt = optionsBuild(testSimpleName, testSimpleName);

        new Runner(opt).run();
    }
}