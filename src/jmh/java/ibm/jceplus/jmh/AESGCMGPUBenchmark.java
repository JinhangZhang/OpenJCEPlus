/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import com.ibm.crypto.plus.provider.GPUAccelerationConfig;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;
import java.util.concurrent.TimeUnit;

/**
 * JMH Benchmark for AES/GCM with GPU acceleration.
 * 
 * This benchmark compares CPU vs GPU performance for different data sizes.
 * 
 * To run with GPU enabled:
 * mvn clean install -DskipTests -Djmh.benchmark.skip=false \
 *   -Djmh.benchmark=ibm.jceplus.jmh.AESGCMGPUBenchmark \
 *   -Dopenjceplus.aes.gcm.gpu.enabled=true
 * 
 * To run with GPU disabled (CPU only):
 * mvn clean install -DskipTests -Djmh.benchmark.skip=false \
 *   -Djmh.benchmark=ibm.jceplus.jmh.AESGCMGPUBenchmark \
 *   -Dopenjceplus.aes.gcm.gpu.enabled=false
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
@Warmup(iterations = 3, time = 2)
@Measurement(iterations = 5, time = 3)
@Fork(value = 1)
public class AESGCMGPUBenchmark {

    private Cipher cipher;
    private SecretKeySpec keySpec;
    private GCMParameterSpec gcmSpec;
    
    @Param({"16384", "65536", "262144", "1048576", "4194304"}) // 16KB, 64KB, 256KB, 1MB, 4MB
    private int dataSize;
    
    private byte[] plaintext;
    private byte[] ciphertext;
    private byte[] key;
    private byte[] iv;
    
    @Setup(Level.Trial)
    public void setupTrial() throws Exception {
        // Register OpenJCEPlus provider
        if (Security.getProvider("OpenJCEPlus") == null) {
            Security.addProvider(new com.ibm.crypto.plus.provider.OpenJCEPlus());
        }
        
        // Print GPU configuration
        System.out.println("=== GPU Acceleration Configuration ===");
        System.out.println(GPUAccelerationConfig.getConfigurationSummary());
        System.out.println("======================================");
        
        // Generate key and IV
        SecureRandom random = new SecureRandom();
        key = new byte[32]; // 256-bit key
        random.nextBytes(key);
        
        iv = new byte[12]; // 96-bit IV
        random.nextBytes(iv);
        
        keySpec = new SecretKeySpec(key, "AES");
        gcmSpec = new GCMParameterSpec(128, iv);
        
        // Get cipher instance
        cipher = Cipher.getInstance("AES/GCM/NoPadding", "OpenJCEPlus");
    }
    
    @Setup(Level.Iteration)
    public void setupIteration() throws Exception {
        // Generate random plaintext for this iteration
        SecureRandom random = new SecureRandom();
        plaintext = new byte[dataSize];
        random.nextBytes(plaintext);
        
        // Pre-encrypt for decryption benchmark
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        ciphertext = cipher.doFinal(plaintext);
    }
    
    @Benchmark
    public void encryptCPU(Blackhole bh) throws Exception {
        // This will use CPU if data size is below threshold or GPU is disabled
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] result = cipher.doFinal(plaintext);
        bh.consume(result);
    }
    
    @Benchmark
    public void decryptCPU(Blackhole bh) throws Exception {
        // This will use CPU if data size is below threshold or GPU is disabled
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        byte[] result = cipher.doFinal(ciphertext);
        bh.consume(result);
    }
    
    @Benchmark
    public void encryptWithAAD(Blackhole bh) throws Exception {
        byte[] aad = "Additional Authenticated Data".getBytes();
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        cipher.updateAAD(aad);
        byte[] result = cipher.doFinal(plaintext);
        bh.consume(result);
    }
    
    @Benchmark
    public void decryptWithAAD(Blackhole bh) throws Exception {
        byte[] aad = "Additional Authenticated Data".getBytes();
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        cipher.updateAAD(aad);
        byte[] result = cipher.doFinal(ciphertext);
        bh.consume(result);
    }
    
    /**
     * Main method for standalone execution.
     */
    public static void main(String[] args) throws Exception {
        org.openjdk.jmh.Main.main(args);
    }
}

// Made with Bob
