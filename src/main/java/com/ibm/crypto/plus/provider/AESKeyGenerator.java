/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;

/**
 * This class generates a secret key for use with the AES algorithm.
 */
public final class AESKeyGenerator extends KeyGeneratorSpi {

    private final OpenJCEPlusProvider provider;
    private int keysize = 16; // default keysize (in bytes)
    private SecureRandom cryptoRandom;

    /**
     * Constructor - initializes provider and SecureRandom for optimal performance.
     * Pre-initializing SecureRandom eliminates null checks during key generation.
     */
    public AESKeyGenerator(OpenJCEPlusProvider provider) {
        if (provider == null) {
            throw new IllegalArgumentException("Provider cannot be null");
        }
        this.provider = provider;
        // Pre-initialize SecureRandom to avoid null check overhead in hot path
        this.cryptoRandom = provider.getSecureRandom(null);
    }

    /**
     * Generates an AES key.
     * Optimized for performance by:
     * - Eliminating null check (cryptoRandom pre-initialized in constructor)
     * - Minimizing exception handling overhead
     * - Ensuring proper cleanup of sensitive key material
     *
     * @return the new AES key
     */
    @Override
    protected SecretKey engineGenerateKey() {
        // Allocate key bytes array - size is fixed and known
        byte[] keyBytes = new byte[this.keysize];
        
        // Generate random key material
        cryptoRandom.nextBytes(keyBytes);

        try {
            // Create AES key - InvalidKeyException should never occur with valid keysize
            return new AESKey(provider, keyBytes);
        } catch (InvalidKeyException e) {
            // Should never happen as keysize is validated in engineInit
            throw new ProviderException(e.getMessage());
        } finally {
            // FIPS requirement: clear sensitive key material from memory
            Arrays.fill(keyBytes, (byte) 0x00);
        }
    }

    /**
     * Initializes this key generator.
     * Optimized: SecureRandom is pre-initialized in constructor, so this method
     * only updates it if a different random source is explicitly provided.
     * 
     * @param random the source of randomness for this generator
     */
    @Override
    protected void engineInit(SecureRandom random) {
        // If in FIPS mode, SecureRandom must be internal and FIPS approved.
        // For FIPS mode, user provided random generator will be ignored.
        // Since cryptoRandom is pre-initialized, only update if needed
        if (random != null) {
            cryptoRandom = provider.getSecureRandom(random);
        }
    }

    /**
     * Initializes this key generator with the specified parameter set and a
     * user-provided source of randomness.
     *
     * @param params
     *            the key generation parameters
     * @param random
     *            the source of randomness for this key generator
     *
     * @exception InvalidAlgorithmParameterException
     *                if <code>params</code> is inappropriate for this key
     *                generator
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
                "AES key generation does not take any parameters");
    }

    /**
     * Initializes this key generator for a certain keysize, using the given
     * source of randomness.
     *
     * @param keysize
     *            the keysize. This is an algorithm-specific metric specified in
     *            number of bits.
     * @param random
     *            the source of randomness for this key generator
     */
    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        if (((keysize % 8) != 0) || (!AESUtils.isKeySizeValid(keysize / 8))) {
            throw new InvalidParameterException("Wrong keysize: must be equal to 128, 192 or 256");
        }

        this.keysize = keysize / 8;
        this.engineInit(random);
    }
}
