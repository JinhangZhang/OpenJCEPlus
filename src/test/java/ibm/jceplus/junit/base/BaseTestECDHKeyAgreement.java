/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECPrivateKeySpec;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class BaseTestECDHKeyAgreement extends BaseTest{
    
    private volatile static boolean clientRenegoReady = false;

    public static void insertProvider(String providerName, String providerClassName, int position) throws Exception{
        Provider provider = java.security.Security.getProvider(providerName);
        if (provider == null) {
            provider = (Provider) Class.forName(providerClassName).getDeclaredConstructor().newInstance();
        }
        java.security.Security.insertProviderAt(provider, position);
    }

    @Test
    private static void testInitWithInvalidKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", providerName);
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();

        KeyFactory keyFactory = KeyFactory.getInstance("EC", providerName);
        ECPrivateKey invalidPrivateKey
                = (ECPrivateKey) keyFactory.generatePrivate(
                        new ECPrivateKeySpec(BigInteger.ZERO,
                                privateKey.getParams()));

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", providerName);

        // The first initiation should succeed.
        ka.init(privateKey);

        // The second initiation should fail with invalid private key,
        // and the private key assigned by the first initiation should be cleared.
        assertThrows(
                InvalidKeyException.class,
                () -> ka.init(invalidPrivateKey));

        // Cannot doPhase due to no private key.
        assertThrows(
                IllegalStateException.class,
                () -> ka.doPhase(kp.getPublic(), true));

        // Cannot generate shared key due to no key
        assertThrows(IllegalStateException.class, ka::generateSecret);
    }

    @Test
    private static void testDoPhaseWithInvalidKey() throws Exception {
        // SECP256R1 key pair
        KeyPairGenerator kpgP256 = KeyPairGenerator.getInstance("EC", providerName);
        kpgP256.initialize(256);
        KeyPair kpP256 = kpgP256.generateKeyPair();

        // SECP384R1 key pair
        KeyPairGenerator kpgP384 = KeyPairGenerator.getInstance("EC", providerName);
        kpgP384.initialize(384);
        KeyPair kpP384 = kpgP384.generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", providerName);
        ka.init(kpP256.getPrivate());

        assertThrows(
                InvalidKeyException.class,
                () -> ka.doPhase(kpP384.getPublic(), true));

        // Should not generate shared key with SECP256R1 private key and SECP384R1 public key
        assertThrows(IllegalStateException.class, ka::generateSecret);
    }
}