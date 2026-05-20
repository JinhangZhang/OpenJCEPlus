/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

/**
 * Configuration for GPU acceleration support using OpenJ9 CUDA API.
 * 
 * GPU acceleration is disabled by default and must be explicitly enabled.
 * It is only available for AES/GCM/NoPadding operations in non-FIPS mode.
 * 
 * Constraints:
 * - Only for large data blocks (configurable threshold)
 * - Only for batch requests (configurable batch size)
 * - Only in non-FIPS mode
 * - CPU fallback is always available
 * - Disabled by default
 * 
 * Uses OpenJ9 CUDA API: com.ibm.cuda package
 * See: https://eclipse.dev/openj9/docs/api/jdk17/openj9.cuda/com/ibm/cuda/package-summary.html
 */
public final class GPUAccelerationConfig {
    
    /**
     * System property to enable GPU acceleration for AES/GCM operations.
     * Default: false (disabled)
     * 
     * Set to "true" to enable GPU acceleration:
     * -Dopenjceplus.aes.gcm.gpu.enabled=true
     */
    public static final String PROPERTY_GPU_ENABLED = "openjceplus.aes.gcm.gpu.enabled";
    
    /**
     * System property to set minimum data size (in bytes) for GPU acceleration.
     * Default: 65536 (64 KB)
     * 
     * GPU acceleration will only be used for data blocks larger than this threshold.
     * Example: -Dopenjceplus.aes.gcm.gpu.minDataSize=131072
     */
    public static final String PROPERTY_GPU_MIN_DATA_SIZE = "openjceplus.aes.gcm.gpu.minDataSize";
    
    /**
     * System property to set minimum batch size for GPU acceleration.
     * Default: 4
     * 
     * GPU acceleration will only be used when processing at least this many operations.
     * Example: -Dopenjceplus.aes.gcm.gpu.minBatchSize=8
     */
    public static final String PROPERTY_GPU_MIN_BATCH_SIZE = "openjceplus.aes.gcm.gpu.minBatchSize";
    
    /**
     * System property to enable CPU fallback on GPU errors.
     * Default: true (enabled)
     * 
     * When true, operations will automatically fall back to CPU if GPU fails.
     * Example: -Dopenjceplus.aes.gcm.gpu.cpuFallback=false
     */
    public static final String PROPERTY_GPU_CPU_FALLBACK = "openjceplus.aes.gcm.gpu.cpuFallback";
    
    /**
     * System property to set CUDA device ID.
     * Default: 0 (first CUDA device)
     * 
     * Specifies which CUDA device to use when multiple GPUs are available.
     * Example: -Dopenjceplus.aes.gcm.gpu.deviceId=1
     */
    public static final String PROPERTY_GPU_DEVICE_ID = "openjceplus.aes.gcm.gpu.deviceId";
    
    // Default values
    private static final int DEFAULT_MIN_DATA_SIZE = 65536; // 64 KB
    private static final int DEFAULT_MIN_BATCH_SIZE = 4;
    private static final int DEFAULT_DEVICE_ID = 0;
    
    // Configuration values (loaded once at class initialization)
    private static final boolean gpuEnabled;
    private static final int minDataSize;
    private static final int minBatchSize;
    private static final boolean cpuFallbackEnabled;
    private static final int deviceId;
    
    // GPU availability status
    private static volatile GPUStatus gpuStatus = GPUStatus.UNKNOWN;
    private static volatile String gpuStatusMessage = "GPU status not yet checked";
    
    static {
        // Load configuration from system properties
        gpuEnabled = Boolean.parseBoolean(System.getProperty(PROPERTY_GPU_ENABLED, "false"));
        minDataSize = Integer.parseInt(System.getProperty(PROPERTY_GPU_MIN_DATA_SIZE, 
                String.valueOf(DEFAULT_MIN_DATA_SIZE)));
        minBatchSize = Integer.parseInt(System.getProperty(PROPERTY_GPU_MIN_BATCH_SIZE, 
                String.valueOf(DEFAULT_MIN_BATCH_SIZE)));
        cpuFallbackEnabled = Boolean.parseBoolean(System.getProperty(PROPERTY_GPU_CPU_FALLBACK, "true"));
        deviceId = Integer.parseInt(System.getProperty(PROPERTY_GPU_DEVICE_ID, 
                String.valueOf(DEFAULT_DEVICE_ID)));
        
        // Validate configuration
        if (minDataSize < 1024) {
            throw new IllegalArgumentException("GPU minimum data size must be at least 1024 bytes");
        }
        if (minBatchSize < 1) {
            throw new IllegalArgumentException("GPU minimum batch size must be at least 1");
        }
        if (deviceId < 0) {
            throw new IllegalArgumentException("GPU device ID must be non-negative");
        }
    }
    
    /**
     * GPU availability status enumeration.
     */
    public enum GPUStatus {
        /** GPU status has not been checked yet */
        UNKNOWN,
        /** GPU is available and initialized successfully */
        AVAILABLE,
        /** GPU is not available (no CUDA hardware or driver issues) */
        UNAVAILABLE,
        /** GPU initialization failed */
        FAILED
    }
    
    /**
     * Private constructor to prevent instantiation.
     */
    private GPUAccelerationConfig() {
    }
    
    /**
     * Check if GPU acceleration is enabled via system property.
     * 
     * @return true if GPU acceleration is enabled, false otherwise
     */
    public static boolean isGPUEnabled() {
        return gpuEnabled;
    }
    
    /**
     * Get the minimum data size threshold for GPU acceleration.
     * 
     * @return minimum data size in bytes
     */
    public static int getMinDataSize() {
        return minDataSize;
    }
    
    /**
     * Get the minimum batch size for GPU acceleration.
     * 
     * @return minimum batch size
     */
    public static int getMinBatchSize() {
        return minBatchSize;
    }
    
    /**
     * Check if CPU fallback is enabled.
     * 
     * @return true if CPU fallback is enabled, false otherwise
     */
    public static boolean isCPUFallbackEnabled() {
        return cpuFallbackEnabled;
    }
    
    /**
     * Get the CUDA device ID to use.
     * 
     * @return CUDA device ID
     */
    public static int getDeviceId() {
        return deviceId;
    }
    
    /**
     * Get the current GPU status.
     * 
     * @return current GPU status
     */
    public static GPUStatus getGPUStatus() {
        return gpuStatus;
    }
    
    /**
     * Get the GPU status message.
     * 
     * @return GPU status message
     */
    public static String getGPUStatusMessage() {
        return gpuStatusMessage;
    }
    
    /**
     * Set the GPU status (package-private, called by GPU initialization code).
     * 
     * @param status new GPU status
     * @param message status message
     */
    static void setGPUStatus(GPUStatus status, String message) {
        gpuStatus = status;
        gpuStatusMessage = message;
    }
    
    /**
     * Check if GPU acceleration should be used for the given data size.
     * 
     * @param dataSize size of data to process in bytes
     * @return true if GPU should be used, false otherwise
     */
    public static boolean shouldUseGPU(int dataSize) {
        return gpuEnabled && 
               gpuStatus == GPUStatus.AVAILABLE && 
               dataSize >= minDataSize;
    }
    
    /**
     * Check if GPU acceleration should be used for the given batch.
     * 
     * @param batchSize number of operations in the batch
     * @param dataSize size of data to process in bytes
     * @return true if GPU should be used, false otherwise
     */
    public static boolean shouldUseGPUForBatch(int batchSize, int dataSize) {
        return gpuEnabled && 
               gpuStatus == GPUStatus.AVAILABLE && 
               batchSize >= minBatchSize && 
               dataSize >= minDataSize;
    }
    
    /**
     * Get a summary of the current GPU configuration.
     * 
     * @return configuration summary string
     */
    public static String getConfigurationSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("GPU Acceleration Configuration (OpenJ9 CUDA):\n");
        sb.append("  Enabled: ").append(gpuEnabled).append("\n");
        sb.append("  Status: ").append(gpuStatus).append(" - ").append(gpuStatusMessage).append("\n");
        sb.append("  Min Data Size: ").append(minDataSize).append(" bytes\n");
        sb.append("  Min Batch Size: ").append(minBatchSize).append("\n");
        sb.append("  CPU Fallback: ").append(cpuFallbackEnabled).append("\n");
        sb.append("  CUDA Device ID: ").append(deviceId).append("\n");
        return sb.toString();
    }
}

// Made with Bob
