/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestPQCSignature extends BaseTestJunit5Signature {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML_DSA_44", "ML-DSA-65", "ML_DSA_87"})
    public void testPQCKeySignature(String Algorithm) throws Exception {

        KeyPair keyPair = generateKeyPair(Algorithm);
        doSignVerify(Algorithm, origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML_DSA_44", "ML-DSA-65", "ML_DSA_87"})
    public void testPQCKeySignatureEncodings(String Algorithm) throws Exception {

        KeyPair keyPair = generateKeyPair(Algorithm);

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        byte[] publicKeyBytes = publicKey.getEncoded();
        byte[] privateKeyBytes = privateKey.getEncoded();

        KeyFactory keyFactory = KeyFactory.getInstance(Algorithm, getProviderName());
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        doSignVerify(Algorithm, origMsg, keyFactory.generatePrivate(privateKeySpec), keyFactory.generatePublic(publicKeySpec));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "ML-DSA-44",
            "ML-DSA-65",
            "ML-DSA-87"
    })
    public void testGenericMLDSASignature(String keyAlgorithm) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm, getProviderName());
        KeyPair keyPair = kpg.generateKeyPair();

        Signature signer = Signature.getInstance("ML-DSA", getProviderName());
        signer.initSign(keyPair.getPrivate());
        signer.update(origMsg);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("ML-DSA", getProviderName());
        verifier.initVerify(keyPair.getPublic());
        verifier.update(origMsg);

        assertTrue(verifier.verify(signature));
    }

    @Test
    public void testSpecificMLDSASignatureRejectsDifferentParameterSet()
            throws Exception {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", getProviderName());
        KeyPair keyPair = kpg.generateKeyPair();

        Signature signer = Signature.getInstance("ML-DSA-44", getProviderName());

        try {
            signer.initSign(keyPair.getPrivate());
            fail("ML-DSA-44 Signature accepted an ML-DSA-65 private key");
        } catch (InvalidKeyException expected) {
            // Expected.
        }

        Signature verifier = Signature.getInstance("ML-DSA-44", getProviderName());

        try {
            verifier.initVerify(keyPair.getPublic());
            fail("ML-DSA-44 Signature accepted an ML-DSA-65 public key");
        } catch (InvalidKeyException expected) {
            // Expected.
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "ML-DSA-44",
            "ML-DSA-65",
            "ML-DSA-87"
    })
    public void testGenericMLDSAKeyFactory(String keyAlgorithm) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm, getProviderName());
        KeyPair keyPair = kpg.generateKeyPair();

        byte[] x509 = keyPair.getPublic().getEncoded();
        byte[] pkcs8 = keyPair.getPrivate().getEncoded();

        KeyFactory genericKeyFactory = KeyFactory.getInstance("ML-DSA", getProviderName());
        PublicKey publicKey = genericKeyFactory.generatePublic(new X509EncodedKeySpec(x509));
        PrivateKey privateKey = genericKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));

        assertNotNull(publicKey);
        assertNotNull(privateKey);
    }


    protected KeyPair generateKeyPair(String Algorithm) throws Exception {
        KeyPairGenerator pqcKeyPairGen = KeyPairGenerator.getInstance(Algorithm, getProviderName());

        return pqcKeyPairGen.generateKeyPair();
    }

}

