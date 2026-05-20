/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.cuda.Cuda;
import com.ibm.cuda.CudaDevice;
import com.ibm.cuda.CudaException;
import com.ibm.cuda.CudaKernel;
import com.ibm.cuda.CudaModule;
import com.ibm.cuda.CudaStream;
import com.ibm.cuda.CudaBuffer;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.ProviderException;

/**
 * CUDA-based GPU accelerator for AES/GCM operations using OpenJ9 CUDA API.
 * 
 * This class provides GPU acceleration for AES/GCM encryption and decryption
 * operations using NVIDIA CUDA through the OpenJ9 CUDA API.
 * 
 * Constraints:
 * - Only for non-FIPS mode
 * - Only for large data blocks (>= configured threshold)
 * - Only for batch operations (>= configured batch size)
 * - CPU fallback available on errors
 * 
 * Thread-safety: This class uses thread-local CUDA streams for thread-safe operation.
 */
public final class CUDAGCMAccelerator {
    
    private static final String CUDA_MODULE_RESOURCE = "/cuda/aes_gcm_kernel.ptx";
    private static final String KERNEL_ENCRYPT_NAME = "aes_gcm_encrypt_kernel";
    private static final String KERNEL_DECRYPT_NAME = "aes_gcm_decrypt_kernel";
    
    // CUDA device and module (shared across threads)
    private static volatile CudaDevice cudaDevice;
    private static volatile CudaModule cudaModule;
    private static volatile CudaKernel encryptKernel;
    private static volatile CudaKernel decryptKernel;
    
    // Thread-local CUDA streams for thread-safe operations
    private static final ThreadLocal<CudaStream> cudaStream = new ThreadLocal<CudaStream>() {
        @Override
        protected CudaStream initialValue() {
            try {
                if (cudaDevice != null) {
                    return new CudaStream(cudaDevice);
                }
            } catch (CudaException e) {
                // Stream creation failed, will use null
            }
            return null;
        }
    };
    
    // Initialization lock
    private static final Object initLock = new Object();
    private static volatile boolean initialized = false;
    
    /**
     * Private constructor to prevent instantiation.
     */
    private CUDAGCMAccelerator() {
    }
    
    /**
     * Initialize CUDA device and load kernels.
     * This method is thread-safe and will only initialize once.
     * 
     * @return true if initialization succeeded, false otherwise
     */
    public static boolean initialize() {
        if (initialized) {
            return cudaDevice != null;
        }
        
        synchronized (initLock) {
            if (initialized) {
                return cudaDevice != null;
            }
            
            try {
                // Check if CUDA is available
                int deviceCount = Cuda.getDeviceCount();
                if (deviceCount == 0) {
                    GPUAccelerationConfig.setGPUStatus(
                        GPUAccelerationConfig.GPUStatus.UNAVAILABLE,
                        "No CUDA devices found");
                    initialized = true;
                    return false;
                }
                
                // Get the configured device
                int deviceId = GPUAccelerationConfig.getDeviceId();
                if (deviceId >= deviceCount) {
                    GPUAccelerationConfig.setGPUStatus(
                        GPUAccelerationConfig.GPUStatus.UNAVAILABLE,
                        "CUDA device " + deviceId + " not found (only " + deviceCount + " devices available)");
                    initialized = true;
                    return false;
                }
                
                // Initialize the CUDA device
                cudaDevice = new CudaDevice(deviceId);
                
                // Load the CUDA module with AES/GCM kernels
                byte[] ptxCode = loadPTXModule();
                if (ptxCode == null) {
                    GPUAccelerationConfig.setGPUStatus(
                        GPUAccelerationConfig.GPUStatus.FAILED,
                        "Failed to load CUDA PTX module");
                    initialized = true;
                    return false;
                }
                
                cudaModule = new CudaModule(cudaDevice, ptxCode);
                
                // Get kernel functions
                encryptKernel = new CudaKernel(cudaModule, KERNEL_ENCRYPT_NAME);
                decryptKernel = new CudaKernel(cudaModule, KERNEL_DECRYPT_NAME);
                
                GPUAccelerationConfig.setGPUStatus(
                    GPUAccelerationConfig.GPUStatus.AVAILABLE,
                    "CUDA device " + deviceId + " initialized successfully: " + 
                    cudaDevice.getName());
                
                initialized = true;
                return true;
                
            } catch (CudaException e) {
                GPUAccelerationConfig.setGPUStatus(
                    GPUAccelerationConfig.GPUStatus.FAILED,
                    "CUDA initialization failed: " + e.getMessage());
                cudaDevice = null;
                cudaModule = null;
                encryptKernel = null;
                decryptKernel = null;
                initialized = true;
                return false;
            } catch (IOException e) {
                GPUAccelerationConfig.setGPUStatus(
                    GPUAccelerationConfig.GPUStatus.FAILED,
                    "Failed to load CUDA module: " + e.getMessage());
                cudaDevice = null;
                initialized = true;
                return false;
            }
        }
    }
    
    /**
     * Load the PTX module containing AES/GCM CUDA kernels.
     * 
     * @return PTX module bytes, or null if loading failed
     * @throws IOException if reading the resource fails
     */
    private static byte[] loadPTXModule() throws IOException {
        try (InputStream is = CUDAGCMAccelerator.class.getResourceAsStream(CUDA_MODULE_RESOURCE)) {
            if (is == null) {
                return null;
            }
            return is.readAllBytes();
        }
    }
    
    /**
     * Encrypt data using CUDA-accelerated AES/GCM.
     * 
     * @param key AES key bytes (16, 24, or 32 bytes)
     * @param iv initialization vector (12 bytes recommended)
     * @param aad additional authenticated data (can be null)
     * @param plaintext plaintext data to encrypt
     * @param ciphertext output buffer for ciphertext (must be at least plaintext.length + tagLength)
     * @param tagLength GCM tag length in bytes (12 or 16)
     * @return number of bytes written to ciphertext buffer
     * @throws CudaException if CUDA operation fails
     * @throws ProviderException if parameters are invalid
     */
    public static int encrypt(byte[] key, byte[] iv, byte[] aad, 
                              byte[] plaintext, byte[] ciphertext, int tagLength) 
            throws CudaException, ProviderException {
        
        if (!initialized || cudaDevice == null) {
            throw new ProviderException("CUDA not initialized");
        }
        
        validateEncryptParams(key, iv, plaintext, ciphertext, tagLength);
        
        CudaStream stream = cudaStream.get();
        if (stream == null) {
            throw new ProviderException("Failed to get CUDA stream for current thread");
        }
        
        // Allocate device memory
        CudaBuffer keyBuffer = null;
        CudaBuffer ivBuffer = null;
        CudaBuffer aadBuffer = null;
        CudaBuffer plaintextBuffer = null;
        CudaBuffer ciphertextBuffer = null;
        
        try {
            // Allocate and copy input data to device
            keyBuffer = new CudaBuffer(cudaDevice, key.length);
            keyBuffer.copyFrom(key);
            
            ivBuffer = new CudaBuffer(cudaDevice, iv.length);
            ivBuffer.copyFrom(iv);
            
            int aadLength = (aad != null) ? aad.length : 0;
            if (aadLength > 0) {
                aadBuffer = new CudaBuffer(cudaDevice, aadLength);
                aadBuffer.copyFrom(aad);
            }
            
            plaintextBuffer = new CudaBuffer(cudaDevice, plaintext.length);
            plaintextBuffer.copyFrom(plaintext);
            
            // Allocate output buffer (ciphertext + tag)
            int outputLength = plaintext.length + tagLength;
            ciphertextBuffer = new CudaBuffer(cudaDevice, outputLength);
            
            // Configure kernel launch parameters
            int blockSize = 256;
            int gridSize = (plaintext.length + blockSize - 1) / blockSize;
            
            // Launch kernel
            encryptKernel.launch(
                gridSize, blockSize,
                stream,
                keyBuffer, key.length,
                ivBuffer, iv.length,
                aadBuffer, aadLength,
                plaintextBuffer, plaintext.length,
                ciphertextBuffer,
                tagLength
            );
            
            // Synchronize stream
            stream.synchronize();
            
            // Copy result back to host
            ciphertextBuffer.copyTo(ciphertext, 0, outputLength);
            
            return outputLength;
            
        } finally {
            // Clean up device memory
            if (keyBuffer != null) keyBuffer.close();
            if (ivBuffer != null) ivBuffer.close();
            if (aadBuffer != null) aadBuffer.close();
            if (plaintextBuffer != null) plaintextBuffer.close();
            if (ciphertextBuffer != null) ciphertextBuffer.close();
        }
    }
    
    /**
     * Decrypt data using CUDA-accelerated AES/GCM.
     * 
     * @param key AES key bytes (16, 24, or 32 bytes)
     * @param iv initialization vector (12 bytes recommended)
     * @param aad additional authenticated data (can be null)
     * @param ciphertext ciphertext data to decrypt (includes tag)
     * @param plaintext output buffer for plaintext
     * @param tagLength GCM tag length in bytes (12 or 16)
     * @return number of bytes written to plaintext buffer
     * @throws CudaException if CUDA operation fails
     * @throws ProviderException if parameters are invalid or authentication fails
     */
    public static int decrypt(byte[] key, byte[] iv, byte[] aad,
                              byte[] ciphertext, byte[] plaintext, int tagLength)
            throws CudaException, ProviderException {
        
        if (!initialized || cudaDevice == null) {
            throw new ProviderException("CUDA not initialized");
        }
        
        validateDecryptParams(key, iv, ciphertext, plaintext, tagLength);
        
        CudaStream stream = cudaStream.get();
        if (stream == null) {
            throw new ProviderException("Failed to get CUDA stream for current thread");
        }
        
        // Allocate device memory
        CudaBuffer keyBuffer = null;
        CudaBuffer ivBuffer = null;
        CudaBuffer aadBuffer = null;
        CudaBuffer ciphertextBuffer = null;
        CudaBuffer plaintextBuffer = null;
        CudaBuffer authResultBuffer = null;
        
        try {
            // Allocate and copy input data to device
            keyBuffer = new CudaBuffer(cudaDevice, key.length);
            keyBuffer.copyFrom(key);
            
            ivBuffer = new CudaBuffer(cudaDevice, iv.length);
            ivBuffer.copyFrom(iv);
            
            int aadLength = (aad != null) ? aad.length : 0;
            if (aadLength > 0) {
                aadBuffer = new CudaBuffer(cudaDevice, aadLength);
                aadBuffer.copyFrom(aad);
            }
            
            ciphertextBuffer = new CudaBuffer(cudaDevice, ciphertext.length);
            ciphertextBuffer.copyFrom(ciphertext);
            
            // Allocate output buffer
            int outputLength = ciphertext.length - tagLength;
            plaintextBuffer = new CudaBuffer(cudaDevice, outputLength);
            
            // Allocate buffer for authentication result (1 byte: 0=fail, 1=success)
            authResultBuffer = new CudaBuffer(cudaDevice, 1);
            
            // Configure kernel launch parameters
            int blockSize = 256;
            int gridSize = (outputLength + blockSize - 1) / blockSize;
            
            // Launch kernel
            decryptKernel.launch(
                gridSize, blockSize,
                stream,
                keyBuffer, key.length,
                ivBuffer, iv.length,
                aadBuffer, aadLength,
                ciphertextBuffer, ciphertext.length,
                plaintextBuffer,
                tagLength,
                authResultBuffer
            );
            
            // Synchronize stream
            stream.synchronize();
            
            // Check authentication result
            byte[] authResult = new byte[1];
            authResultBuffer.copyTo(authResult);
            if (authResult[0] == 0) {
                throw new ProviderException("GCM tag verification failed");
            }
            
            // Copy result back to host
            plaintextBuffer.copyTo(plaintext, 0, outputLength);
            
            return outputLength;
            
        } finally {
            // Clean up device memory
            if (keyBuffer != null) keyBuffer.close();
            if (ivBuffer != null) ivBuffer.close();
            if (aadBuffer != null) aadBuffer.close();
            if (ciphertextBuffer != null) ciphertextBuffer.close();
            if (plaintextBuffer != null) plaintextBuffer.close();
            if (authResultBuffer != null) authResultBuffer.close();
        }
    }
    
    /**
     * Validate encryption parameters.
     */
    private static void validateEncryptParams(byte[] key, byte[] iv, byte[] plaintext,
                                              byte[] ciphertext, int tagLength) {
        if (key == null || (key.length != 16 && key.length != 24 && key.length != 32)) {
            throw new ProviderException("Invalid key length: must be 16, 24, or 32 bytes");
        }
        if (iv == null || iv.length == 0) {
            throw new ProviderException("IV cannot be null or empty");
        }
        if (plaintext == null) {
            throw new ProviderException("Plaintext cannot be null");
        }
        if (ciphertext == null || ciphertext.length < plaintext.length + tagLength) {
            throw new ProviderException("Ciphertext buffer too small");
        }
        if (tagLength != 12 && tagLength != 16) {
            throw new ProviderException("Invalid tag length: must be 12 or 16 bytes");
        }
    }
    
    /**
     * Validate decryption parameters.
     */
    private static void validateDecryptParams(byte[] key, byte[] iv, byte[] ciphertext,
                                              byte[] plaintext, int tagLength) {
        if (key == null || (key.length != 16 && key.length != 24 && key.length != 32)) {
            throw new ProviderException("Invalid key length: must be 16, 24, or 32 bytes");
        }
        if (iv == null || iv.length == 0) {
            throw new ProviderException("IV cannot be null or empty");
        }
        if (ciphertext == null || ciphertext.length <= tagLength) {
            throw new ProviderException("Ciphertext too short");
        }
        if (plaintext == null || plaintext.length < ciphertext.length - tagLength) {
            throw new ProviderException("Plaintext buffer too small");
        }
        if (tagLength != 12 && tagLength != 16) {
            throw new ProviderException("Invalid tag length: must be 12 or 16 bytes");
        }
    }
    
    /**
     * Check if CUDA acceleration is available and initialized.
     * 
     * @return true if CUDA is available, false otherwise
     */
    public static boolean isAvailable() {
        if (!initialized) {
            initialize();
        }
        return cudaDevice != null;
    }
    
    /**
     * Clean up CUDA resources.
     * This should be called during shutdown.
     */
    public static void cleanup() {
        synchronized (initLock) {
            try {
                if (encryptKernel != null) {
                    encryptKernel.close();
                    encryptKernel = null;
                }
                if (decryptKernel != null) {
                    decryptKernel.close();
                    decryptKernel = null;
                }
                if (cudaModule != null) {
                    cudaModule.close();
                    cudaModule = null;
                }
                if (cudaDevice != null) {
                    cudaDevice.close();
                    cudaDevice = null;
                }
            } catch (Exception e) {
                // Ignore cleanup errors
            }
            initialized = false;
        }
    }
}

// Made with Bob
