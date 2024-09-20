/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECPrivateKeySpec;
import javax.crypto.KeyAgreement;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class BaseTestECDHKeyAgreement extends BaseTestJunit5 {

    @Test
    public void testInitWithInvalidKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", getProviderName());
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();

        KeyFactory keyFactory = KeyFactory.getInstance("EC", getProviderName());
        ECPrivateKey invalidPrivateKey
                = (ECPrivateKey) keyFactory.generatePrivate(
                        new ECPrivateKeySpec(BigInteger.ZERO,
                                privateKey.getParams()));

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", getProviderName());

        // The first initiation should succeed.
        ka.init(privateKey);

        // The second initiation should fail with invalid private key,
        // and the private key assigned by the first initiation should be cleared.
        Assertions.assertThrows(
            java.security.InvalidKeyException.class,
            () -> ka.init(invalidPrivateKey);
        );
        // try {
        //     ka.init(invalidPrivateKey);
        // } catch (java.security.InvalidKeyException ike) {
        //     System.out.println("Expected <java.security.InvalidKeyException> is caught.");
        // }

        // Cannot doPhase due to no private key.
        Assertions.assertThrows(
            java.lang.IllegalStateException.class,
            () -> ka.doPhase(kp.getPublic(), true);
        );
        // try {
        //     ka.doPhase(kp.getPublic(), true);
        // } catch (java.lang.IllegalStateException ise) {
        //     System.out.println("Expected <java.lang.IllegalStateException> is caught.");
        // }

        // Cannot generate shared key due to no key
        Assertions.assertThrows(
            java.lang.IllegalStateException.class,
            () -> ka.generateSecret();
        );
        // try {
        //     ka.generateSecret();
        // } catch (java.lang.IllegalStateException ise) {
        //     System.out.println("Expected <java.lang.IllegalStateException> is caught.");
        // }
    }

    @Test
    public void testDoPhaseWithInvalidKey() throws Exception {
        // SECP256R1 key pair
        KeyPairGenerator kpgP256 = KeyPairGenerator.getInstance("EC", getProviderName());
        kpgP256.initialize(256);
        KeyPair kpP256 = kpgP256.generateKeyPair();

        // SECP384R1 key pair
        KeyPairGenerator kpgP384 = KeyPairGenerator.getInstance("EC", getProviderName());
        kpgP384.initialize(384);
        KeyPair kpP384 = kpgP384.generateKeyPair();

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", getProviderName());
        ka.init(kpP256.getPrivate());

        Assertions.assertThrows(
            java.security.InvalidKeyException.class,
            () -> ka.doPhase(kpP384.getPublic(), true);
        );
        // try {
        //     ka.doPhase(kpP384.getPublic(), true);
        // } catch (java.security.InvalidKeyException ise) {
        //     System.out.println("Expected <java.security.InvalidKeyException> is caught.");
        // }

        // Should not generate shared key with SECP256R1 private key and SECP384R1 public key
        Assertions.assertThrows(
            java.lang.IllegalStateException.class,
            () -> ka.generateSecret();
        );
        // try {
        //     ka.generateSecret();
        // } catch (java.lang.IllegalStateException ise) {
        //     System.out.println("Expected <java.lang.IllegalStateException> is caught.");
        // }
    }
}
