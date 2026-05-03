/*
 * Copyright IBM Corp. 2025, 2026
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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestKEM extends BaseTestJunit5 {


    protected KeyPairGenerator pqcKeyPairGen;
    protected KeyFactory pqcKeyFactory;

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML_KEM_768", "ML_KEM_1024"})
    public void testKEM(String Algorithm) throws Exception {

        KEM kem = KEM.getInstance(Algorithm, getProviderName());

        KeyPair pqcKeyPair = generateKeyPair(Algorithm);

        KEM.Encapsulator encr = kem.newEncapsulator(pqcKeyPair.getPublic());
        KEM.Encapsulated enc = encr.encapsulate(0, 32, "AES");

        SecretKey keyE = enc.key();
       
        KEM.Decapsulator decr = kem.newDecapsulator(pqcKeyPair.getPrivate());
        SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 32, "AES");
        
        assertArrayEquals(keyE.getEncoded(), keyD.getEncoded(), "Secrets do NOT match");
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML_KEM_768", "ML_KEM_1024"})
    public void testKEMEmptyNoToFrom(String Algorithm) throws Exception {

        KEM kem = KEM.getInstance(Algorithm, getProviderName());

        KeyPair pqcKeyPair = generateKeyPair(Algorithm);

        KEM.Encapsulator encr = kem.newEncapsulator(pqcKeyPair.getPublic());
        KEM.Encapsulated enc = encr.encapsulate();

        SecretKey keyE = enc.key();
       
        KEM.Decapsulator decr = kem.newDecapsulator(pqcKeyPair.getPrivate());
        SecretKey keyD = decr.decapsulate(enc.encapsulation());
        
        assertArrayEquals(keyE.getEncoded(), keyD.getEncoded(), "Secrets do NOT match");
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML_KEM_768", "ML_KEM_1024"})
    public void testKEMError(String Algorithm) throws Exception {
        KEM.Encapsulated enc = null;

        KEM kem = KEM.getInstance(Algorithm, getProviderName());

        KeyPair pqcKeyPair = generateKeyPair(Algorithm);

        KEM.Encapsulator encr = kem.newEncapsulator(pqcKeyPair.getPublic());
        for (int i = 0; i < 4; i++) {
            int from = 0;
            int to = 0;
            switch (i) {
                case 0:
                    from = 0;
                    to = 33;
                    break;
                case 1:
                    from = -1;
                    to = 32;
                    break;
                case 2:
                    from = 20;
                    to = 15;
                    break;
                case 3:
                    from = 32;
                    to = 32;
                    break;
            }
            try {
                enc = encr.encapsulate(from, to, "AES");
                fail("testKEMError failed -Encapsulated length's test failed.");
            } catch (IndexOutOfBoundsException iob) {
            }
        }

        try {
            enc = encr.encapsulate(0, 32, null);
            fail("testKEMError failed -Encapsulated null alg worked.");
        } catch (NullPointerException iob) {
        }

        enc = encr.encapsulate(0, 32, "AES");
       
        KEM.Decapsulator decr = kem.newDecapsulator(pqcKeyPair.getPrivate());
        for (int i = 0; i < 4; i++) {
            int from = 0;
            int to = 0;
            switch (i) {
                case 0:
                    from = 0;
                    to = 33;
                    break;
                case 1:
                    from = -1;
                    to = 32;
                    break;
                case 2:
                    from = 20;
                    to = 15;
                    break;
                case 3:
                    from = 32;
                    to = 32;
                    break;
            }
            try {
                decr.decapsulate(enc.encapsulation(), from, to, "AES");
                fail("testKEMError failed -Decapsulate length's test failed.");
            } catch (IndexOutOfBoundsException iob) {
            }
        }

        try {
            decr.decapsulate(enc.encapsulation(), 0, 32, null);
            fail("testKEMError failed -Decapsulate alg null worked.");
        } catch (NullPointerException iob) {
        }
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML_KEM_768", "ML_KEM_1024"})
    public void testKEMSmallerSecret(String Algorithm) throws Exception {

        KEM kem = KEM.getInstance(Algorithm, getProviderName());

        KeyPair pqcKeyPair = generateKeyPair(Algorithm);

        KEM.Encapsulator encr = kem.newEncapsulator(pqcKeyPair.getPublic());
        KEM.Encapsulated enc = encr.encapsulate(0, 16, "AES");

        SecretKey keyE = enc.key();

        KEM.Decapsulator decr = kem.newDecapsulator(pqcKeyPair.getPrivate());
        SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 16, "AES");
        
        assertArrayEquals(keyE.getEncoded(), keyD.getEncoded(), "Secrets do NOT match");
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML_KEM_768", "ML_KEM_1024"})
    public void testKEMKeys(String Algorithm) throws Exception {

        KEM kem = KEM.getInstance(Algorithm, getProviderName());

        KeyPair pqcKeyPair = generateKeyPair("RSA");

        try {
            kem.newEncapsulator(pqcKeyPair.getPublic());
            fail("testKEMKeys failed - RSA Public key did not cause an InvalidKeyException.");
        } catch (InvalidKeyException ike) {
            assertTrue(ike.getMessage().equals("unsupported key"));
        }
  
        try {
            kem.newDecapsulator(pqcKeyPair.getPrivate());
            fail("testKEMKeys failed - RSA Private key did not cause an InvalidKeyException.");
        } catch (InvalidKeyException ike) {
            assertTrue(ike.getMessage().equals("unsupported key"));
        }

        // Test null keys
        PublicKey pub = null;
        PrivateKey priv = null;

        try {
            kem.newEncapsulator(pub);
            fail("testKEMKeys failed - NULL Public key did not cause an InvalidKeyException.");
        } catch (InvalidKeyException ike) {
            assertTrue(ike.getMessage().equals("Key is null."));
        }
  
        try {
            kem.newDecapsulator(priv);
            fail("testKEMKeys failed - NULL Private key did not cause an InvalidKeyException.");
        } catch (InvalidKeyException ike) {
            assertTrue(ike.getMessage().equals("Key is null."));
        }
    }

    /**
     * Tests that decapsulation fails with a DecapsulateException when attempting to decapsulate
     * an encapsulation message that was created with a different ML-KEM algorithm variant.
     *
     * <p>This test verifies that the KEM implementation properly validates the encapsulation
     * message length during decapsulation. Each ML-KEM variant (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
     * produces encapsulation messages of different lengths. When a decapsulator receives an
     * encapsulation message with an incorrect length (from a different variant), it should
     * reject it with a DecapsulateException containing an appropriate error message.
     *
     * <p>Test procedure:
     * <ol>
     *   <li>Generate a key pair using the first algorithm (keyAlgorithm)</li>
     *   <li>Generate a different key pair using a second algorithm (wrongAlgorithm)</li>
     *   <li>Create an encapsulation using the second key pair (wrong length for first algorithm)</li>
     *   <li>Attempt to decapsulate using the first key pair's private key</li>
     *   <li>Verify that a DecapsulateException is thrown with the expected error message</li>
     * </ol>
     *
     * @param keyAlgorithm the ML-KEM algorithm variant to use for the decapsulation key pair
     * @param wrongAlgorithm the ML-KEM algorithm variant to use for creating the encapsulation
     *                       (produces wrong length for keyAlgorithm)
     * @throws Exception if an unexpected error occurs during test execution
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512,ML-KEM-768", "ML-KEM-768,ML-KEM-1024", "ML-KEM-1024,ML-KEM-512"})
    public void testKEMInvalidEncapsulationLength(String keyAlgorithm, String wrongAlgorithm) throws Exception {
        // Generate a key pair with one algorithm
        KeyPair keyPair = generateKeyPair(keyAlgorithm);
        
        // Create encapsulation with a different algorithm (wrong length)
        KEM kemWrong = KEM.getInstance(wrongAlgorithm, getProviderName());
        KeyPair wrongKeyPair = generateKeyPair(wrongAlgorithm);
        KEM.Encapsulator encapsulator = kemWrong.newEncapsulator(wrongKeyPair.getPublic());
        KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, 32, "AES");
        
        // Try to decapsulate with the original key (wrong length)
        KEM kem = KEM.getInstance(keyAlgorithm, getProviderName());
        KEM.Decapsulator decapsulator = kem.newDecapsulator(keyPair.getPrivate());
        
        try {
            decapsulator.decapsulate(encapsulated.encapsulation(), 0, 32, "AES");
            fail("testKEMInvalidEncapsulationLength failed - Invalid encapsulation length did not cause a DecapsulateException for " + keyAlgorithm + " with " + wrongAlgorithm + " encapsulation");
        } catch (javax.crypto.DecapsulateException de) {
            assertTrue(de.getMessage().contains("Invalid key encapsulation message length"),
                "Expected error message about invalid encapsulation length, but got: " + de.getMessage());
            assertTrue(de.getMessage().contains(keyAlgorithm),
                "Expected error message to mention key algorithm " + keyAlgorithm + ", but got: " + de.getMessage());
        }
    }

    protected KeyPair generateKeyPair(String Algorithm) throws Exception {
        pqcKeyPairGen = KeyPairGenerator.getInstance(Algorithm, getProviderName());

        KeyPair keyPair = pqcKeyPairGen.generateKeyPair();
        if (keyPair.getPrivate() == null) {
            fail("Private key is null");
        }

        if (keyPair.getPublic() == null) {
            fail("RPublic key is null");
        }

        if (!(keyPair.getPrivate() instanceof PrivateKey)) {
            fail("Key is not a PrivateKey");
        }

        if (!(keyPair.getPublic() instanceof PublicKey)) {
            fail("Key is not a PublicKey");
        }

        return keyPair;
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML_KEM_768", "ML_KEM_1024"})
    protected void keyFactoryCreateFromEncoded(String Algorithm) throws Exception {

        pqcKeyFactory = KeyFactory.getInstance(Algorithm, getProviderName());
        KeyPair pqcKeyPair = generateKeyPair(Algorithm);
        
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(pqcKeyPair.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(
                pqcKeyPair.getPrivate().getEncoded());

        PublicKey pub =  pqcKeyFactory.generatePublic(x509Spec);
        PrivateKey priv =  pqcKeyFactory.generatePrivate(pkcs8Spec);

        assertArrayEquals(pub.getEncoded(), pqcKeyPair.getPublic().getEncoded(),
                    "Public key does not match generated public key");
        assertArrayEquals(priv.getEncoded(), pqcKeyPair.getPrivate().getEncoded(),
                    "Private key does not match generated public key");
    }
}

