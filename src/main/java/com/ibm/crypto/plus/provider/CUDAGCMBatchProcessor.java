/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.cuda.CudaException;
import java.security.ProviderException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Batch processor for CUDA-accelerated AES/GCM operations.
 * 
 * This class manages batching of AES/GCM operations to maximize GPU utilization.
 * Operations are queued until the batch size threshold is reached, then processed
 * together on the GPU.
 * 
 * Thread-safety: This class is thread-safe and uses locks to coordinate batch processing.
 */
public final class CUDAGCMBatchProcessor {
    
    /**
     * Represents a single GCM operation in a batch.
     */
    public static class GCMOperation {
        public final boolean encrypt;
        public final byte[] key;
        public final byte[] iv;
        public final byte[] aad;
        public final byte[] input;
        public final byte[] output;
        public final int tagLength;
        public Exception exception;
        public int outputLength;
        
        public GCMOperation(boolean encrypt, byte[] key, byte[] iv, byte[] aad,
                           byte[] input, byte[] output, int tagLength) {
            this.encrypt = encrypt;
            this.key = key;
            this.iv = iv;
            this.aad = aad;
            this.input = input;
            this.output = output;
            this.tagLength = tagLength;
        }
    }
    
    // Thread-local batch queue
    private static final ThreadLocal<List<GCMOperation>> batchQueue = 
        ThreadLocal.withInitial(ArrayList::new);
    
    // Lock for batch processing
    private static final ReentrantLock batchLock = new ReentrantLock();
    
    /**
     * Private constructor to prevent instantiation.
     */
    private CUDAGCMBatchProcessor() {
    }
    
    /**
     * Add an operation to the batch queue.
     * If the batch size threshold is reached, the batch is processed immediately.
     * 
     * @param operation the GCM operation to add
     * @return true if operation was processed, false if queued
     */
    public static boolean addToBatch(GCMOperation operation) {
        List<GCMOperation> queue = batchQueue.get();
        queue.add(operation);
        
        // Check if we should process the batch
        if (queue.size() >= GPUAccelerationConfig.getMinBatchSize()) {
            processBatch();
            return true;
        }
        
        return false;
    }
    
    /**
     * Process all queued operations in the current thread's batch.
     * This method processes operations sequentially but on the GPU.
     */
    public static void processBatch() {
        List<GCMOperation> queue = batchQueue.get();
        if (queue.isEmpty()) {
            return;
        }
        
        batchLock.lock();
        try {
            // Process each operation
            for (GCMOperation op : queue) {
                try {
                    if (op.encrypt) {
                        op.outputLength = CUDAGCMAccelerator.encrypt(
                            op.key, op.iv, op.aad, op.input, op.output, op.tagLength);
                    } else {
                        op.outputLength = CUDAGCMAccelerator.decrypt(
                            op.key, op.iv, op.aad, op.input, op.output, op.tagLength);
                    }
                } catch (CudaException | ProviderException e) {
                    op.exception = e;
                }
            }
        } finally {
            queue.clear();
            batchLock.unlock();
        }
    }
    
    /**
     * Flush the current thread's batch queue, processing any pending operations.
     */
    public static void flush() {
        processBatch();
    }
    
    /**
     * Clear the current thread's batch queue without processing.
     */
    public static void clear() {
        batchQueue.get().clear();
    }
    
    /**
     * Get the current batch queue size for the current thread.
     * 
     * @return number of operations in the queue
     */
    public static int getBatchSize() {
        return batchQueue.get().size();
    }
    
    /**
     * Process a single operation immediately without batching.
     * This is used when batching is not beneficial or when immediate processing is required.
     * 
     * @param operation the GCM operation to process
     * @throws Exception if the operation fails
     */
    public static void processImmediate(GCMOperation operation) throws Exception {
        try {
            if (operation.encrypt) {
                operation.outputLength = CUDAGCMAccelerator.encrypt(
                    operation.key, operation.iv, operation.aad, 
                    operation.input, operation.output, operation.tagLength);
            } else {
                operation.outputLength = CUDAGCMAccelerator.decrypt(
                    operation.key, operation.iv, operation.aad,
                    operation.input, operation.output, operation.tagLength);
            }
        } catch (CudaException | ProviderException e) {
            operation.exception = e;
            throw e;
        }
    }
}

// Made with Bob
