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
        System.out.println("PQCPrivateKey(keyBytes, algName)algName = " + algName);
        System.out.println("PQCPrivateKey(keyBytes, algName)name = " + this.name);

        System.out.println("PQCPrivateKey(keyBytes, algName)input keyBytes length = " + keyBytes.length);
        System.out.print("PQCPrivateKey(keyBytes, algName)input keyBytes first bytes = ");
        for (int i = 0; i < Math.min(32, keyBytes.length); i++) {
            System.out.printf("%02X ", keyBytes[i] & 0xFF);
        }
        System.out.println();

        checkEncoding(this.name, keyBytes);
        // Currently the ICC expects the raw keys in an OctetString
        key = keyBytes;
        try {
            try {
                if (isExpanded(this.name, key)) {
                    System.out.println("This is a expanded key, use the keyBytes directly");
                    this.pqcKey = PQCKey.createPrivateKey(
                                this.name, key, provider);
                    this.privKeyMaterial = keyBytes.clone();
                } else if (isSeedOnly(this.name, key)) {
                    System.out.println("This is a seed only key, wrapping it in an OctetString");
                    pkOct = new DerValue(DerValue.tag_OctetString, key);
                    byte[] pkOctBytes = pkOct.toByteArray();
                    System.out.println("PQCPrivateKey(keyBytes, algName)pkOctBytes length = " + pkOctBytes.length);
                    System.out.print("PQCPrivateKey(keyBytes, algName)pkOctBytes first bytes = ");
                    for (int i = 0; i < Math.min(32, pkOctBytes.length); i++) {
                        System.out.printf("%02X ", pkOctBytes[i] & 0xFF);
                    }
                    System.out.println();
                    this.pqcKey = PQCKey.createPrivateKey(
                                this.name, pkOctBytes, provider);
                    this.privKeyMaterial = keyBytes.clone();
                } else {
                    System.out.println("This is a not a seed/expanded key, maybe a RAW keyBytes");
                    pkOct = new DerValue(DerValue.tag_OctetString, key);
                    byte[] pkOctBytes = pkOct.toByteArray();
                    System.out.println("PQCPrivateKey(keyBytes, algName)pkOctBytes length = " + pkOctBytes.length);
                    System.out.print("PQCPrivateKey(keyBytes, algName)pkOctBytes first bytes = ");
                    for (int i = 0; i < Math.min(32, pkOctBytes.length); i++) {
                        System.out.printf("%02X ", pkOctBytes[i] & 0xFF);
                    }
                    System.out.println();
                    this.pqcKey = PQCKey.createPrivateKey(
                                this.name, pkOctBytes, provider);
                    this.privKeyMaterial = pkOctBytes;
                }
                

                System.out.println("PQCPrivateKey(keyBytes, algName)this.privKeyMaterial length = " + this.privKeyMaterial.length);
                System.out.print("PQCPrivateKey(keyBytes, algName)this.privKeyMaterial first bytes = ");
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
            this.name = PQCKnownOIDs.findMatch(pqcKey.getAlgorithm()).stdName();
            this.algid = new AlgorithmId(PQCAlgorithmId.getOID(name));

            System.out.println("===== PQCPrivateKey(pqcKey) =====");
            System.out.println("PQCPrivateKey(pqcKey)pqcKey = " + pqcKey);
            System.out.println("PQCPrivateKey(pqcKey)pqcKey algorithm = " + pqcKey.getAlgorithm());

            byte[] pqcPrivateBytes = pqcKey.getPrivateKeyBytes();

            System.out.println("PQCPrivateKey(pqcKey)pqcKey private bytes length = " + pqcPrivateBytes.length);
            System.out.print("PQCPrivateKey(pqcKey)pqcKey private bytes first bytes = ");
            for (int i = 0; i < Math.min(32, pqcPrivateBytes.length); i++) {
                System.out.printf("%02X ", pqcPrivateBytes[i] & 0xFF);
            }
            System.out.println();

            checkEncoding(this.name, pqcPrivateBytes);
            //Check to determine if the key bytes have the Octet tag.
            if (isSeedOnly(this.name, pqcPrivateBytes)) {
                System.out.println("PQCPrivateKey(pqcKey)pqcPrivateBytes is seed");
            } else if (isExpanded(this.name, pqcPrivateBytes)) {
                System.out.println("PQCPrivateKey(pqcKey)pqcPrivateBytes is expanded");
            } else {
                throw new InvalidKeyException("ICC only generates seed/expanded for now.");
            }
            this.privKeyMaterial = pqcPrivateBytes;
        } catch (Exception exception) {
            throw provider.providerException("Failure in PQCPrivateKey" + exception.getMessage(), exception);
        }
    }

    /**
     * Create a private key from it's DER encoding (PKCS#8).
     *
     * 
     * @param encoded   the encoded PKCS#8 key
     */
    PQCPrivateKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        super(encoded);
        this.provider = provider;
        System.out.println("===== PQCPrivateKey(encoded) =====");

        /**
         * 
         * input encoded length = 54
         * input encoded first bytes = 30 34 02 01 00 30 0B 06 09 60 86 48 01 65 03 04 03 12 04 22 80 20 FB BE 4B 73 57 D1 30 9C C4 05 
         * 
         */
        System.out.println("PQCPrivateKey(encoded)input encoded length = " + encoded.length);
        System.out.print("PQCPrivateKey(encoded)input encoded first bytes = ");
        for (int i = 0; i < Math.min(32, encoded.length); i++) {
            System.out.printf("%02X ", encoded[i] & 0xFF);
        }
        System.out.println();

        System.out.println("PQCPrivateKey(encoded)after super(encoded), privKeyMaterial length = " + this.privKeyMaterial.length);
        System.out.print("PQCPrivateKey(encoded)after super(encoded), privKeyMaterial first bytes = ");
        for (int i = 0; i < Math.min(32, this.privKeyMaterial.length); i++) {
            System.out.printf("%02X ", this.privKeyMaterial[i] & 0xFF);
        }
        System.out.println();
        /*
         * after super(encoded), privKeyMaterial length = 34
         * after super(encoded), privKeyMaterial first bytes = 80 20 FB BE 4B 73 57 D1 30 9C C4 05 21 5C 6E AB 7D 26 01 CC 8C 3B AD 74 C0 D9 25 8F CE 25 57 DA 
         * OctectStringEncoded: key length = 34
         * OctectStringEncoded: key first bytes = 80 20 FB BE 4B 73 57 D1 30 9C C4 05 21 5C 6E AB 7D 26 01 CC 8C 3B AD 74 C0 D9 25 8F CE 25 57 DA 
         * privKeyMaterial is NOT OctetStringEncoded, wrapping it
         */ 
        this.name = PQCKnownOIDs.findMatch(this.algid.getName()).stdName();

        checkEncoding(this.name, this.privKeyMaterial);
        //Check to determine if the key bytes have the Octet tag.
        DerValue pkOct = null;
        try {
            if (isSeedOnly(this.name, this.privKeyMaterial)) {
                System.out.println("PQCPrivateKey(encoded)privKeyMaterial is seed");
                pkOct = new DerValue(DerValue.tag_OctetString, this.privKeyMaterial);
                byte[] pkOctBytes = pkOct.toByteArray();
                this.pqcKey = PQCKey.createPrivateKey(
                                this.name, pkOctBytes, provider);
                System.out.println("PQCPrivateKey(encoded)pkOctBytes length = " + pkOctBytes.length);
                System.out.print("PQCPrivateKey(encoded)pkOctBytes first bytes = ");
                for (int i = 0; i < Math.min(32, pkOctBytes.length); i++) {
                    System.out.printf("%02X ", pkOctBytes[i] & 0xFF);
                }
                System.out.println();
            } else if (isExpanded(this.name, this.privKeyMaterial)) {
                System.out.println("PQCPrivateKey(encoded)privKeyMaterial is expanded");
                this.pqcKey = PQCKey.createPrivateKey(
                                this.name, this.privKeyMaterial, provider);
            } else {
                System.out.println("This is a not a seed/expanded key, throw exception");
                throw new InvalidKeyException("This is a not a seed/expanded key, throw exception");
            }
        } catch (Exception e) {
            throw new InvalidKeyException("Invalid key " + e.getMessage(), e);
        } finally {
            if (pkOct != null) {
                pkOct.clear();
            }
        }
    }

    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return name;
    }

    @Override
    public byte[] getEncoded() {
        System.out.println("===== PQCPrivateKey.getEncoded() =====");
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

            System.out.println("PQCPrivateKey(getEncoded)privKeyMaterial length = "
            + (this.privKeyMaterial == null ? "null" : this.privKeyMaterial.length));
            System.out.println("PQCPrivateKey(getEncoded)privKeyMaterial first bytes = "
                    + toHex(this.privKeyMaterial, 32));

            System.out.println("PQCPrivateKey(getEncoded)encodedKey length = "
                    + (encodedKey == null ? "null" : encodedKey.length));
            System.out.println("PQCPrivateKey(getEncoded)encodedKey first bytes = "
                    + toHex(encodedKey, 64));

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

    private static String toHex(byte[] data, int maxLen) {
        if (data == null) {
            return "null";
        }

        StringBuilder sb = new StringBuilder();
        int len = Math.min(data.length, maxLen);

        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02X ", data[i] & 0xff));
        }

        return sb.toString();
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

    private boolean isSeedOnly(String algName, byte[] key) {
        if (key == null || key.length < 2) {
            return false;
        }

        int seedLen;

        if (algName.startsWith("ML-DSA")) {
            seedLen = 32;
        } else if (algName.startsWith("ML-KEM")) {
            seedLen = 64;
        } else {
            return false;
        }

        return (key.length == seedLen + 2)
                && ((key[0] & 0xFF) == 0x80)
                && ((key[1] & 0xFF) == seedLen);
    }

    private boolean isExpanded(String algName, byte[] key) {
        try {
            if (key == null || key.length < 4) {
                return false;
            }

            // expandedKey OCTET STRING
            if ((key[0] & 0xFF) != 0x04) {
                return false;
            }

            // Only accept: 04 82 LL LL <expanded key bytes>
            if ((key[1] & 0xFF) != 0x82) {
                return false;
            }

            int len = ((key[2] & 0xFF) << 8) | (key[3] & 0xFF);

            if (len != key.length - 4) {
                return false;
            }

            return len == getExpandedPrivateKeyLength(algName);
        } catch (Exception e) {
            return false;
        }
    }

    private int getExpandedPrivateKeyLength(String algName) {
        switch (algName) {
            case "ML-KEM-512":
                return 1632;
            case "ML-KEM":
            case "ML-KEM-768":
                return 2400;
            case "ML-KEM-1024":
                return 3168;

            case "ML-DSA-44":
                return 2560;
            case "ML-DSA":
            case "ML-DSA-65":
                return 4032;
            case "ML-DSA-87":
                return 4896;

            default:
                return -1;
        }
    }

    private void checkEncoding(String algName, byte[] keyBytes) throws InvalidKeyException {
        if (keyBytes == null || keyBytes.length == 0) {
            throw new InvalidKeyException("Invalid " + this.name
                    + " private key encoding: null or empty key bytes");
        }
        // if (!isSeedOnly(algName, keyBytes) && !isExpanded(algName, keyBytes)) {
        //     throw new InvalidKeyException("Invalid " + this.name
        //             + " private key encoding: key bytes are neither seed nor expanded key");
        // }
    }
}
