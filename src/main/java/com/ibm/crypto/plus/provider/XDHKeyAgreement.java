/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.NativeCryptoSelector;
import com.ibm.crypto.plus.provider.base.NativeException;
import com.ibm.crypto.plus.provider.base.NativeInterface;
import com.ibm.crypto.plus.provider.base.XECKey;
import java.util.Arrays;
import java.util.Optional;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

abstract class XDHKeyAgreement extends KeyAgreementSpi {

    private OpenJCEPlusProvider provider = null;
    private NativeInterface backend;
    private String curveName;
    private XECKey ockXecKeyPub = null;
    private XECKey ockXecKeyPriv = null;
    private byte[] secret;
    private String alg = null;

    XDHKeyAgreement(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    XDHKeyAgreement(OpenJCEPlusProvider provider, String Alg) {
        this.provider = provider;
        this.alg = Alg;
    }

    /**
     * Executes the next phase of this key agreement with the given key that was
     * received from one of the other parties involved in this key agreement.
     *
     * @param key       the key for this phase. For example, in the case of
     *                  Diffie-Hellman between 2 parties, this would be the other
     *                  party's Diffie-Hellman public key.
     * @param lastPhase flag which indicates whether or not this is the last phase of
     *                  this key agreement.
     * @return the (intermediate) key resulting from this phase, or null if this
     * phase does not yield a key (which is the case of X25519/X448 keys)
     * @throws InvalidKeyException   if the given key is inappropriate for this phase.
     * @throws IllegalStateException if this key agreement has not been initialized.
     */

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {
        clearSecret();
        ockXecKeyPub = null;

        if (ockXecKeyPriv == null) {
            throw new IllegalStateException("KeyAgreement is not initialized");
        }
        if (!lastPhase) {
            throw new IllegalStateException("XDH can only be between two parties");
        }
        if (!(key instanceof XECPublicKey publicKey)) {
            throw new InvalidKeyException("Unsupported key type");
        }
        if (!(publicKey.getParams() instanceof NamedParameterSpec params)
                || !curveName.equalsIgnoreCase(params.getName())) {
            throw new InvalidKeyException(
                    "Public and private key parameters must match");
        }

        try {
            if (key instanceof XDHPublicKeyImpl local
                    && local.getOCKKey().getBackendInterface() == backend) {
                ockXecKeyPub = local.getOCKKey();
            } else {
                ockXecKeyPub = new XDHPublicKeyImpl(
                        provider, params, publicKey.getU(),
                        alg == null ? "XDH" : alg, backend).getOCKKey();
            }

            secret = XECKey.computeECDHSecret(
                    ockXecKeyPub, ockXecKeyPriv, backend);

            int nonzero = 0;
            for (byte value : secret) {
                nonzero |= value;
            }
            if (nonzero == 0) {
                clearSecret();
                throw new InvalidKeyException("Point has small order");
            }
        } catch (NativeException | InvalidAlgorithmParameterException
                | java.security.InvalidParameterException e) {
            throw new InvalidKeyException("Failed to generate XDH secret", e);
        }

        return null;
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        if (secret == null)
            throw new IllegalStateException("Wrong state");
        if (ockXecKeyPriv == null || ockXecKeyPub == null)
            throw new IllegalStateException("private/public key is not received");

        byte[] result = secret;

        // Reset the key agreement here (in case anything goes wrong)
        secret = null;

        return result;
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
        if (algorithm == null)
            throw new NoSuchAlgorithmException("Algorithm must not be null");
        if (!(algorithm.equalsIgnoreCase("TlsPremasterSecret")
                || algorithm.equalsIgnoreCase("Generic"))) {
            throw new NoSuchAlgorithmException(
                    "Unsupported secret key algorithm: " + algorithm);
        }
        return new SecretKeySpec(engineGenerateSecret(), algorithm);
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException {
        if (secret == null) {
            throw new IllegalStateException("Wrong state");
        }

        if (sharedSecret == null || offset < 0 || offset > sharedSecret.length
                || secret.length > sharedSecret.length - offset) {
            throw new ShortBufferException(
                    "Insufficient buffer for shared secret");
        }

        int length = secret.length;
        System.arraycopy(secret, 0, sharedSecret, offset, length);
        clearSecret();
        return length;
    }

    /**
     * Initializes this key agreement with the given key and source of
     * randomness. The given key is required to contain all the algorithm
     * parameters required for this key agreement.
     *
     * <p>
     * If the key agreement algorithm requires random bytes, it gets them from
     * the given source of randomness, <code>random</code>. However, if the
     * underlying algorithm implementation does not require any random bytes,
     * <code>random</code> is ignored.
     *
     * @param key    the party's private information. For example, in the case of
     *               the Diffie-Hellman key agreement, this would be the party's
     *               own Diffie-Hellman private key.
     * @param random Added to satisfy API but never used. Can be null.
     * @throws InvalidKeyException if the given key is inappropriate for this key agreement,
     *                             e.g., is of the wrong type or has an incompatible
     *                             algorithm type.
     */

    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        try {
            engineInit(key, null, random);
        } catch (InvalidAlgorithmParameterException e) {
            // never happens, because we did not pass any parameters
        }

    }

    /**
     * Initializes this key agreement with the given key, set of algorithm
     * parameters, and source of randomness.
     *
     * @param key    the party's private information. For example, in the case of
     *               the Diffie-Hellman key agreement, this would be the party's
     *               own Diffie-Hellman private key.
     * @param params Added to satisfy API but never used. Can be null.
     * @param random Added to satisfy API but never used. Can be null.
     * @throws InvalidKeyException                if the given key is inappropriate for this key agreement,
     *                                            e.g., is of the wrong type or has an incompatible
     *                                            algorithm type.
     * @throws InvalidAlgorithmParameterException if the given parameters are inappropriate for this key
     *                                            agreement.
     */

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params,
            SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        clearSecret();
        ockXecKeyPriv = null;
        ockXecKeyPub = null;
        curveName = null;

        if (!(key instanceof XECPrivateKey privateKey)
                || !(privateKey.getParams() instanceof NamedParameterSpec keyParams)) {
            throw new InvalidKeyException("Unsupported key type or parameters");
        }

        String name = keyParams.getName();
        CurveUtil.getXCurve(keyParams);

        if (alg != null && !alg.equalsIgnoreCase(name)) {
            throw new InvalidKeyException("Incompatible XDH parameters: " + name);
        }

        if (params != null
                && (!(params instanceof NamedParameterSpec requested)
                        || !name.equalsIgnoreCase(requested.getName()))) {
            throw new InvalidAlgorithmParameterException(
                    "Parameters do not match private key");
        }

        backend = NativeCryptoSelector.selectBackend(
                provider, "KeyAgreement", alg == null ? "XDH" : alg);

        if (key instanceof XDHPrivateKeyImpl local
                && local.getOCKKey().getBackendInterface() == backend) {
            ockXecKeyPriv = local.getOCKKey();
        } else {
            byte[] scalar = privateKey.getScalar().orElseThrow(
                    () -> new InvalidKeyException(
                            "Private key scalar is unavailable"));
            try {
                ockXecKeyPriv = new XDHPrivateKeyImpl(
                        provider, keyParams, Optional.of(scalar),
                        alg == null ? "XDH" : alg, backend).getOCKKey();
            } catch (RuntimeException e) {
                throw new InvalidKeyException(
                        "Unable to import XDH private key", e);
            } finally {
                Arrays.fill(scalar, (byte) 0);
            }
        }

        curveName = name;
    }

    private void clearSecret() {
        if (secret != null) {
            Arrays.fill(secret, (byte) 0);
            secret = null;
        }
    }

    public static final class X25519 extends XDHKeyAgreement {
        public X25519(OpenJCEPlusProvider provider) {
            super(provider, "X25519");
        }
    }

    public static final class X448 extends XDHKeyAgreement {
        public X448(OpenJCEPlusProvider provider) {
            super(provider, "X448");
        }
    }

    public static final class XDH extends XDHKeyAgreement {
        public XDH(OpenJCEPlusProvider provider) {
            super(provider);
        }
    }
}
