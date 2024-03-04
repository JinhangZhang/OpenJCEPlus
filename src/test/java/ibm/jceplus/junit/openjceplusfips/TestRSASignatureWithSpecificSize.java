/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.openjceplusfips;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.InvalidParameterException;

import junit.framework.Test;
import junit.framework.TestSuite;

public class TestRSASignatureWithSpecificSize extends ibm.jceplus.junit.base.BaseTest {

    //--------------------------------------------------------------------------
    //
    //
    static final byte[] origMsg = "this is the original message to be signed I changed to a very long message to make sure enough bytes are there for copying."
            .getBytes();

    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestRSASignatureWithSpecificSize() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    // RSA signature sign allows at least 2048 bits of RSA key to be used for sign a signature.
    public byte[] doSign(String sigAlgo, byte[] message, PrivateKey privateKey) throws Exception {
        Signature sign = Signature.getInstance(sigAlgo, Utils.TEST_SUITE_PROVIDER_NAME);
        try {
            sign.initSign(privateKey);
        } catch (InvalidParameterException ipe) {
            if ("RSA keys must be at least 2048 bits long".equals(ipe.getMessage())) {
                System.out.println("Expected exception msg: <RSA keys must be at least 2048 bits long> is caught for sign.");
                return null;
            } else if ("In FIPS mode, only 2048, 3072, or 4096 size of RSA key is accepted.".equals(ipe.getMessage())) {
                System.out.println("Expected exception msg: <In FIPS mode, only 2048, 3072, or 4096 size of RSA key is accepted.> is caught for sign.");
                return null;
            } else {
                throw ipe;
            }
        }
        sign.update(message);
        byte[] signedBytes = sign.sign();
        return signedBytes;
    }

    // RSA signature verify allows at least 2048 bits of RSA key to be used for sign a signature.
    public void doVerify(String sigAlgo, byte[] message, PublicKey publicKey, 
            byte[] signedBytes) throws Exception {
        Signature verify = Signature.getInstance(sigAlgo, Utils.TEST_SUITE_PROVIDER_NAME);
        try {
            verify.initVerify(publicKey);
        } catch (InvalidParameterException ipe) {
            if ("RSA keys must be at least 1024 bits long".equals(ipe.getMessage())) {
                System.out.println("Expected exception msg: <RSA keys must be at least 1024 bits long> is caught for verify.");
                return;
            } else if ("In FIPS mode, only 1024, 2048, 3072, or 4096 size of RSA key is accepted.".equals(ipe.getMessage())) {
                System.out.println("Expected exception msg: <In FIPS mode, only 1024, 2048, 3072, or 4096 size of RSA key is accepted.> is caught for verify.");
                return;
            } else {
                throw ipe;
            }
        }
        verify.update(message);
        if (signedBytes != null) {
            assertTrue("Signature verification failed", verify.verify(signedBytes));
        } else {
            assertFalse("Signature verification failed", verify.verify(signedBytes));
        }
    }

    // Use a non FIPS provider to get a 1024 bits of RSA key.
    public KeyPair generateKeyPair(int keysize) throws Exception {
        KeyPairGenerator rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", Utils.PROVIDER_SunRsaSign);
        rsaKeyPairGen.initialize(keysize);
        return rsaKeyPairGen.generateKeyPair();
    }

    public void testSHA256withRSA_1024() throws Exception {
        KeyPair keyPair = generateKeyPair(1024);
        System.out.println("Keysize is 1024");
        byte[] signedBytes = doSign("SHA256withRSA", origMsg, keyPair.getPrivate());
        doVerify("SHA256withRSA", origMsg, keyPair.getPublic(), signedBytes);
    }

    public void testSHA256withRSA_2048() throws Exception {
        KeyPair keyPair = generateKeyPair(2048);
        System.out.println("Keysize is 2048");
        byte[] signedBytes = doSign("SHA256withRSA", origMsg, keyPair.getPrivate());
        doVerify("SHA256withRSA", origMsg, keyPair.getPublic(), signedBytes);
    }

    public void testSHA256withRSA_3072() throws Exception {
        KeyPair keyPair = generateKeyPair(3072);
        System.out.println("Keysize is 3072");
        byte[] signedBytes = doSign("SHA256withRSA", origMsg, keyPair.getPrivate());
        doVerify("SHA256withRSA", origMsg, keyPair.getPublic(), signedBytes);
    }

    public void testSHA256withRSA_4096() throws Exception {
        KeyPair keyPair = generateKeyPair(4096);
        System.out.println("Keysize is 4096");
        byte[] signedBytes = doSign("SHA256withRSA", origMsg, keyPair.getPrivate());
        doVerify("SHA256withRSA", origMsg, keyPair.getPublic(), signedBytes);
    }

    // check large size
    public void testSHA256withRSA_5120() throws Exception {
        KeyPair keyPair = generateKeyPair(5120);
        System.out.println("Keysize is 5120");
        byte[] signedBytes = doSign("SHA256withRSA", origMsg, keyPair.getPrivate());
        doVerify("SHA256withRSA", origMsg, keyPair.getPublic(), signedBytes);
    }

    // check small size
    public void testSHA256withRSA_512() throws Exception {
        KeyPair keyPair = generateKeyPair(512);
        System.out.println("Keysize is 512");
        byte[] signedBytes = doSign("SHA256withRSA", origMsg, keyPair.getPrivate());
        doVerify("SHA256withRSA", origMsg, keyPair.getPublic(), signedBytes);
    }

    // check size not in the list
    public void testSHA256withRSA_1032() throws Exception {
        KeyPair keyPair = generateKeyPair(1032);
        System.out.println("Keysize is 1032");
        byte[] signedBytes = doSign("SHA256withRSA", origMsg, keyPair.getPrivate());
        doVerify("SHA256withRSA", origMsg, keyPair.getPublic(), signedBytes);
    }

    // check size not in the list
    public void testSHA256withRSA_2056() throws Exception {
        KeyPair keyPair = generateKeyPair(2056);
        System.out.println("keysize is 2056");
        byte[] signedBytes = doSign("SHA256withRSA", origMsg, keyPair.getPrivate());
        doVerify("SHA256withRSA", origMsg, keyPair.getPublic(), signedBytes);
    }

    //--------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        junit.textui.TestRunner.run(suite());
    }

    //--------------------------------------------------------------------------
    //
    //
    public static Test suite() {
        TestSuite suite = new TestSuite(TestRSASignatureWithSpecificSize.class);
        return suite;
    }
}
