/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.PQCKey;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;

/*
 * A PQC private key for the NIST FIPS 203, 204, 205 Algorithm.
 */
@SuppressWarnings("restriction")
final class PQCPrivateKey extends PKCS8Key {

    private static final long serialVersionUID = -3168962080315231494L;

    private OpenJCEPlusProvider provider = null;
    private final String name;

    private transient PQCKey pqcKey;

    private transient boolean destroyed = false;

    /**
     * Create a PQC private key from the key data and the algorithm name.
     *
     * @param keyBytes  the private key bytes
     * @param algName   the name of the algorithm used
     */
    PQCPrivateKey(OpenJCEPlusProvider provider, byte[] keyBytes, String algName)
            throws InvalidKeyException {
        this.algid = new AlgorithmId(PQCAlgorithmId.getOID(algName));
        this.name = PQCKnownOIDs.findMatch(this.algid.getName()).stdName();
        this.provider = provider;
        byte[] key = null;
        DerValue pkOct = null;
        
        System.out.println("===== PQCPrivateKey(keyBytes, algName) =====");
        System.out.println("algName = " + algName);
        System.out.println("name = " + this.name);

        System.out.println("input keyBytes length = " + keyBytes.length);
        System.out.print("input keyBytes first bytes = ");
        for (int i = 0; i < Math.min(32, keyBytes.length); i++) {
            System.out.printf("%02X ", keyBytes[i] & 0xFF);
        }
        System.out.println();

        //Check to determine if the key bytes already have the Octet tag.
        if (OctectStringEncoded(keyBytes)) {
            //Remove encoding OctetString encoding.
            System.out.println("Key is OctetString encoded, removing encoding");
            key = Arrays.copyOfRange(keyBytes, 4, keyBytes.length);
        } else {
            System.out.println("Key is not OctetString encoded");
            key = keyBytes;
        }

        System.out.println("key length = " + key.length);
        System.out.print("key first bytes = ");
        for (int i = 0; i < Math.min(32, key.length); i++) {
            System.out.printf("%02X ", key[i] & 0xFF);
        }
        System.out.println();

        // Currently the ICC expects the raw keys in an OctetString
        try {
            try {
                pkOct = new DerValue(DerValue.tag_OctetString, key);
                byte[] pkOctBytes = pkOct.toByteArray();
                System.out.println("pkOctBytes length = " + pkOctBytes.length);
                System.out.print("pkOctBytes first bytes = ");
                for (int i = 0; i < Math.min(32, pkOctBytes.length); i++) {
                    System.out.printf("%02X ", pkOctBytes[i] & 0xFF);
                }
                System.out.println();

                this.pqcKey = PQCKey.createPrivateKey(
                                this.name, pkOct.toByteArray(), provider);
                this.privKeyMaterial = pkOct.toByteArray();

                System.out.println("this.privKeyMaterial length = " + this.privKeyMaterial.length);
                System.out.print("this.privKeyMaterial first bytes = ");
                for (int i = 0; i < Math.min(32, this.privKeyMaterial.length); i++) {
                    System.out.printf("%02X ", this.privKeyMaterial[i] & 0xFF);
                }
                System.out.println();

            } finally {
                pkOct.clear();
            }
        } catch (Exception e) {
            throw new InvalidKeyException("Invalid key " + e.getMessage(), e);
        }
    }

    /**
     * Create a PQC private key from an existing PQCKey.
     *
     * @param pqcKey the PQCKey to be used to create the private key
     */
    PQCPrivateKey(OpenJCEPlusProvider provider, PQCKey pqcKey) throws InvalidKeyException {
        try {
            this.provider = provider;
            this.pqcKey = pqcKey;

            System.out.println("===== PQCPrivateKey(pqcKey) =====");
            System.out.println("pqcKey = " + pqcKey);
            System.out.println("pqcKey algorithm = " + pqcKey.getAlgorithm());

            byte[] pqcPrivateBytes = pqcKey.getPrivateKeyBytes();

            System.out.println("pqcKey private bytes length = " + pqcPrivateBytes.length);
            System.out.print("pqcKey private bytes first bytes = ");
            for (int i = 0; i < Math.min(32, pqcPrivateBytes.length); i++) {
                System.out.printf("%02X ", pqcPrivateBytes[i] & 0xFF);
            }
            System.out.println();

            //Check to determine if the key bytes have the Octet tag.
            if (OctectStringEncoded(pqcKey.getPrivateKeyBytes())) {
                System.out.println("privKeyMaterial uses pqcPrivateBytes directly");
                this.privKeyMaterial = pqcKey.getPrivateKeyBytes();
            } else {
                DerValue pkOct = null;
                try {
                    pkOct = new DerValue(DerValue.tag_OctetString, pqcKey.getPrivateKeyBytes());

                    byte[] pkOctBytes = pkOct.toByteArray();
                    System.out.println("pkOctBytes length = " + pkOctBytes.length);
                    System.out.print("pkOctBytes first bytes = ");
                    for (int i = 0; i < Math.min(32, pkOctBytes.length); i++) {
                        System.out.printf("%02X ", pkOctBytes[i] & 0xFF);
                    }
                    System.out.println();

                    this.privKeyMaterial = pkOct.toByteArray();
                    System.out.println("this.privKeyMaterial length = " + this.privKeyMaterial.length);
                    System.out.print("this.privKeyMaterial first bytes = ");
                    for (int i = 0; i < Math.min(32, this.privKeyMaterial.length); i++) {
                        System.out.printf("%02X ", this.privKeyMaterial[i] & 0xFF);
                    }
                    System.out.println();

                } finally {
                    pkOct.clear();
                }
            }

            this.name = PQCKnownOIDs.findMatch(pqcKey.getAlgorithm()).stdName();
            this.algid = new AlgorithmId(PQCAlgorithmId.getOID(name));
        } catch (Exception exception) {
            throw provider.providerException("Failure in PQCPrivateKey" + exception.getMessage(), exception);
        }
    }

    /**
     * Create a private key from it's DER encoding (PKCS#8).
     *
     * @param encoded   the encoded PKCS#8 key
     */
    PQCPrivateKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        super(encoded);
        this.provider = provider;

        System.out.println("===== PQCPrivateKey(encoded) =====");

        System.out.println("input encoded length = " + encoded.length);
        System.out.print("input encoded first bytes = ");
        for (int i = 0; i < Math.min(32, encoded.length); i++) {
            System.out.printf("%02X ", encoded[i] & 0xFF);
        }
        System.out.println();

        System.out.println("after super(encoded), privKeyMaterial length = " + this.privKeyMaterial.length);
        System.out.print("after super(encoded), privKeyMaterial first bytes = ");
        for (int i = 0; i < Math.min(32, this.privKeyMaterial.length); i++) {
            System.out.printf("%02X ", this.privKeyMaterial[i] & 0xFF);
        }
        System.out.println();

        this.name = PQCKnownOIDs.findMatch(this.algid.getName()).stdName();

        //Check to determine if the key bytes have the Octet tag.
        if (!(OctectStringEncoded(this.privKeyMaterial))) {
            System.out.println("privKeyMaterial is NOT OctetStringEncoded, wrapping it");
            DerValue pkOct = null;
            try {
                pkOct = new DerValue(DerValue.tag_OctetString, this.privKeyMaterial);

                byte[] pkOctBytes = pkOct.toByteArray();

                System.out.println("pkOctBytes length = " + pkOctBytes.length);
                System.out.print("pkOctBytes first bytes = ");
                for (int i = 0; i < Math.min(32, pkOctBytes.length); i++) {
                    System.out.printf("%02X ", pkOctBytes[i] & 0xFF);
                }
                System.out.println();

                this.privKeyMaterial = pkOct.toByteArray();
            } finally {
                pkOct.clear();
            }
        }
        try {
            System.out.println("before PQCKey.createPrivateKey, privKeyMaterial length = "
            + this.privKeyMaterial.length);
            System.out.print("before PQCKey.createPrivateKey, privKeyMaterial first bytes = ");
            for (int i = 0; i < Math.min(32, this.privKeyMaterial.length); i++) {
                System.out.printf("%02X ", this.privKeyMaterial[i] & 0xFF);
            }
            System.out.println();

            this.pqcKey = PQCKey.createPrivateKey(
                                this.name, this.privKeyMaterial, provider);
        } catch (Exception e) {
            throw new InvalidKeyException("Invalid key " + e.getMessage(), e);
        }
    }

    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return name;
    }

    @Override
    public byte[] getEncoded() {
        checkDestroyed();
        /*Different JVM levels are resulting in different encodings. So do the encoding here instead.
        *     OneAsymmetricKey ::= SEQUENCE {
        *        version                   Version,
        *        privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
        *        privateKey                PrivateKey,
        *        attributes            [0] Attributes OPTIONAL,
        *        ...,
        *        [[2: publicKey        [1] PublicKey OPTIONAL ]],
        *        ...
        *      }
        */
        byte[] encodedKey = null;
        try {
            int V1 = 0;
            DerOutputStream tmp = new DerOutputStream();
            tmp.putInteger(V1);
            DerOutputStream bytes = new DerOutputStream();
            bytes.putOID(algid.getOID());
            tmp.write(DerValue.tag_Sequence, bytes);
            tmp.putOctetString(this.privKeyMaterial);
            DerValue out = DerValue.wrap(DerValue.tag_Sequence, tmp);
            encodedKey = out.toByteArray();
            tmp.close();
            bytes.close();
        } catch (IOException ex) {
            //System.out.println("Exception creating encoding - "+ex.getMessage());
            return encodedKey;
        }
        
        return encodedKey;
    }

    PQCKey getPQCKey() {
        return this.pqcKey;
    }

    @java.io.Serial
    protected Object writeReplace() throws java.io.ObjectStreamException {
        checkDestroyed();
        return new JCEPlusKeyRep(JCEPlusKeyRep.Type.PRIVATE, getAlgorithm(), getFormat(), getEncoded(), provider.getName());
    } 

    /**
     * Destroys this key. A call to any of its other methods after this will
     * cause an IllegalStateException to be thrown.
     *
     * @throws DestroyFailedException
     *                                if some error occurs while destroying this
     *                                key.
     */
    @Override
    public void destroy() throws DestroyFailedException {
        if (!destroyed) {
            destroyed = true;
            Arrays.fill(this.privKeyMaterial, 0, this.privKeyMaterial.length, (byte) 0x00);
            this.privKeyMaterial = null;
            this.encodedKey = null;
            this.pqcKey = null;
        }
    }

    /** Determines if this key has been destroyed. */
    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    private void checkDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("This key is no longer valid");
        }
    }

    private boolean OctectStringEncoded(byte[] key) {
        if (key == null) {
            System.out.println("key = null");
        } else {
            System.out.println("OctectStringEncoded: key length = " + key.length);

            System.out.print("OctectStringEncoded: key first bytes = ");
            for (int i = 0; i < Math.min(32, key.length); i++) {
                System.out.printf("%02X ", key[i] & 0xFF);
            }
            System.out.println();
        }

        try {
            //Check and see if this is an encoded OctetString
            if (key[0] == 0x04) {
                //This might be encoded
                StringBuilder sb = new StringBuilder();
                for (int i = 2; i < 4; i++) {
                    sb.append(String.format("%02X", key[i]));
                }
                String s = sb.toString();
                int b =  Integer.parseInt(s, 16);
                if (b == (key.length - 4)) {
                    //This is an encoding
                    return true;
                }
            } 
            return false;
        } catch (Exception e) {
            return false;
        }
    }

}
