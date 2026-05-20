/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openjceplus;

import com.ibm.crypto.plus.provider.GPUAccelerationConfig;
import com.ibm.crypto.plus.provider.CUDAGCMAccelerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test GPU acceleration for AES/GCM operations.
 * 
 * These tests only run when GPU acceleration is enabled and available.
 * To run these tests, set the system property:
 * -Dopenjceplus.aes.gcm.gpu.enabled=true
 */
public class TestGPUAcceleration extends ibm.jceplus.junit.base.BaseTestAESGCM {

    @BeforeAll
    public static void setUp() throws Exception {
        // Ensure OpenJCEPlus provider is registered
        if (Security.getProvider("OpenJCEPlus") == null) {
            Security.addProvider(new com.ibm.crypto.plus.provider.OpenJCEPlus());
        }
    }

    /**
     * Check if GPU acceleration is available for testing.
     */
    static boolean isGPUAvailable() {
        return GPUAccelerationConfig.isGPUEnabled() && 
               CUDAGCMAccelerator.isAvailable();
    }

    @Test
    @EnabledIf("isGPUAvailable")
    public void testGPUConfiguration() {
        System.out.println("=== GPU Configuration Test ===");
        System.out.println(GPUAccelerationConfig.getConfigurationSummary());
        
        assertTrue(GPUAccelerationConfig.isGPUEnabled(), 
            "GPU acceleration should be enabled");
        assertEquals(GPUAccelerationConfig.GPUStatus.AVAILABLE, 
            GPUAccelerationConfig.getGPUStatus(),
            "GPU should be available");
        assertTrue(GPUAccelerationConfig.getMinDataSize() > 0,
            "Minimum data size should be positive");
        assertTrue(GPUAccelerationConfig.getMinBatchSize() > 0,
            "Minimum batch size should be positive");
    }

    @Test
    @EnabledIf("isGPUAvailable")
    public void testGPUEncryptionLargeData() throws Exception {
        System.out.println("=== GPU Encryption Test (Large Data) ===");
        
        // Use data size larger than threshold to trigger GPU acceleration
        int dataSize = GPUAccelerationConfig.getMinDataSize() + 1024;
        
        // Generate random key and IV
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[32]; // 256-bit key
        random.nextBytes(key);
        
        byte[] iv = new byte[12]; // 96-bit IV
        random.nextBytes(iv);
        
        // Generate random plaintext
        byte[] plaintext = new byte[dataSize];
        random.nextBytes(plaintext);
        
        // Encrypt with GPU acceleration
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "OpenJCEPlus");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        assertNotNull(ciphertext, "Ciphertext should not be null");
        assertEquals(plaintext.length + 16, ciphertext.length, 
            "Ciphertext should be plaintext length + tag length");
        
        // Decrypt and verify
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);
        
        assertArrayEquals(plaintext, decrypted, 
            "Decrypted data should match original plaintext");
        
        System.out.println("Successfully encrypted and decrypted " + dataSize + " bytes");
    }

    @Test
    @EnabledIf("isGPUAvailable")
    public void testGPUDecryptionLargeData() throws Exception {
        System.out.println("=== GPU Decryption Test (Large Data) ===");
        
        int dataSize = GPUAccelerationConfig.getMinDataSize() + 2048;
        
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[16]; // 128-bit key
        random.nextBytes(key);
        
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        
        byte[] plaintext = new byte[dataSize];
        random.nextBytes(plaintext);
        
        // Encrypt first
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "OpenJCEPlus");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        // Decrypt with GPU acceleration
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);
        
        assertArrayEquals(plaintext, decrypted,
            "GPU-decrypted data should match original plaintext");
        
        System.out.println("Successfully decrypted " + dataSize + " bytes");
    }

    @Test
    @EnabledIf("isGPUAvailable")
    public void testGPUWithAAD() throws Exception {
        System.out.println("=== GPU Test with Additional Authenticated Data ===");
        
        int dataSize = GPUAccelerationConfig.getMinDataSize() + 512;
        
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[24]; // 192-bit key
        random.nextBytes(key);
        
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        
        byte[] aad = "Additional Authenticated Data".getBytes();
        
        byte[] plaintext = new byte[dataSize];
        random.nextBytes(plaintext);
        
        // Encrypt with AAD
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "OpenJCEPlus");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        cipher.updateAAD(aad);
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        // Decrypt with AAD
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        cipher.updateAAD(aad);
        byte[] decrypted = cipher.doFinal(ciphertext);
        
        assertArrayEquals(plaintext, decrypted,
            "Decrypted data with AAD should match original plaintext");
        
        System.out.println("Successfully processed " + dataSize + " bytes with AAD");
    }

    @Test
    @EnabledIf("isGPUAvailable")
    public void testGPUSmallDataFallback() throws Exception {
        System.out.println("=== GPU Small Data Fallback Test ===");
        
        // Use data size smaller than threshold - should use CPU
        int dataSize = GPUAccelerationConfig.getMinDataSize() / 2;
        
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[32];
        random.nextBytes(key);
        
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        
        byte[] plaintext = new byte[dataSize];
        random.nextBytes(plaintext);
        
        // This should use CPU, not GPU
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "OpenJCEPlus");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        byte[] decrypted = cipher.doFinal(ciphertext);
        
        assertArrayEquals(plaintext, decrypted,
            "Small data should still work correctly (using CPU)");
        
        System.out.println("Successfully processed small data (" + dataSize + " bytes) with CPU fallback");
    }

    @Test
    @EnabledIf("isGPUAvailable")
    public void testGPUMultipleOperations() throws Exception {
        System.out.println("=== GPU Multiple Operations Test ===");
        
        int dataSize = GPUAccelerationConfig.getMinDataSize() + 1024;
        int numOperations = 5;
        
        SecureRandom random = new SecureRandom();
        
        for (int i = 0; i < numOperations; i++) {
            byte[] key = new byte[32];
            random.nextBytes(key);
            
            byte[] iv = new byte[12];
            random.nextBytes(iv);
            
            byte[] plaintext = new byte[dataSize];
            random.nextBytes(plaintext);
            
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "OpenJCEPlus");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);
            
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] decrypted = cipher.doFinal(ciphertext);
            
            assertArrayEquals(plaintext, decrypted,
                "Operation " + (i + 1) + " should produce correct result");
        }
        
        System.out.println("Successfully completed " + numOperations + " operations");
    }

    @Test
    @EnabledIf("isGPUAvailable")
    public void testGPUDifferentKeySizes() throws Exception {
        System.out.println("=== GPU Different Key Sizes Test ===");
        
        int dataSize = GPUAccelerationConfig.getMinDataSize() + 512;
        int[] keySizes = {16, 24, 32}; // 128, 192, 256 bits
        
        SecureRandom random = new SecureRandom();
        
        for (int keySize : keySizes) {
            byte[] key = new byte[keySize];
            random.nextBytes(key);
            
            byte[] iv = new byte[12];
            random.nextBytes(iv);
            
            byte[] plaintext = new byte[dataSize];
            random.nextBytes(plaintext);
            
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "OpenJCEPlus");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);
            
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] decrypted = cipher.doFinal(ciphertext);
            
            assertArrayEquals(plaintext, decrypted,
                "Key size " + (keySize * 8) + " bits should work correctly");
            
            System.out.println("Successfully tested " + (keySize * 8) + "-bit key");
        }
    }

    @Test
    public void testGPUDisabledByDefault() {
        System.out.println("=== GPU Disabled By Default Test ===");
        
        // This test runs even when GPU is not enabled
        // It verifies that GPU is disabled by default
        
        if (!System.getProperty("openjceplus.aes.gcm.gpu.enabled", "false").equals("true")) {
            assertFalse(GPUAccelerationConfig.isGPUEnabled(),
                "GPU acceleration should be disabled by default");
            System.out.println("Confirmed: GPU acceleration is disabled by default");
        } else {
            System.out.println("GPU acceleration is explicitly enabled via system property");
        }
    }
}

// Made with Bob
