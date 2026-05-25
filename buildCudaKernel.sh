#!/bin/bash
#
# Copyright IBM Corp. 2026
#
# Build script for compiling CUDA kernels to PTX format
#

set -e

echo "=== Building CUDA AES/GCM Kernel ==="

# Check if nvcc is available
if ! command -v nvcc &> /dev/null; then
    echo "ERROR: nvcc (NVIDIA CUDA Compiler) not found"
    echo "Please install CUDA Toolkit from: https://developer.nvidia.com/cuda-downloads"
    exit 1
fi

# Display CUDA version
echo "CUDA Compiler version:"
nvcc --version

# Source and destination paths
CUDA_SOURCE="src/main/resources/cuda/aes_gcm_kernel.cu"
PTX_OUTPUT="src/main/resources/cuda/aes_gcm_kernel.ptx"

# Check if source file exists
if [ ! -f "$CUDA_SOURCE" ]; then
    echo "ERROR: CUDA source file not found: $CUDA_SOURCE"
    exit 1
fi

echo "Compiling CUDA kernel..."
echo "Source: $CUDA_SOURCE"
echo "Output: $PTX_OUTPUT"

# Compile CUDA to PTX
# -ptx: Generate PTX code
# --gpu-architecture: Target GPU architecture (sm_52 = Maxwell, widely compatible)
# -O3: Optimization level 3
# --use_fast_math: Use fast math operations
nvcc -ptx "$CUDA_SOURCE" \
     -o "$PTX_OUTPUT" \
     --gpu-architecture=sm_52 \
     -O3 \
     --use_fast_math

if [ $? -eq 0 ]; then
    echo "✓ CUDA kernel compiled successfully"
    echo "✓ PTX file generated: $PTX_OUTPUT"
    
    # Display PTX file size
    PTX_SIZE=$(wc -c < "$PTX_OUTPUT")
    echo "✓ PTX file size: $PTX_SIZE bytes"
    
    # Verify PTX file
    if [ -s "$PTX_OUTPUT" ]; then
        echo "✓ PTX file verification passed"
    else
        echo "ERROR: PTX file is empty"
        exit 1
    fi
else
    echo "ERROR: CUDA compilation failed"
    exit 1
fi

echo ""
echo "=== Build Complete ==="
echo ""
echo "Next steps:"
echo "1. Run tests: mvn test -Dtest=TestGPUAcceleration -Dopenjceplus.aes.gcm.gpu.enabled=true"
echo "2. Run benchmarks: mvn clean install -DskipTests -Djmh.benchmark.skip=false -Djmh.benchmark=ibm.jceplus.jmh.AESGCMGPUBenchmark -Dopenjceplus.aes.gcm.gpu.enabled=true"
echo ""

# Made with Bob
