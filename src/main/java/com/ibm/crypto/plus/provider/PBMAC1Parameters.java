/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.KnownOIDs;
import sun.security.util.ObjectIdentifier;

/**
 * This class implements the parameter set used with password-based
 * mac scheme 1 (PBMAC1), which is defined in PKCS#5 as follows:
 *
 * <pre>
 * -- PBMAC1
 *
 * PBMAC1Algorithms ALGORITHM-IDENTIFIER ::=
 *   { {PBMAC1-params IDENTIFIED BY id-PBMAC1}, ...}
 *
 * id-PBMAC1 OBJECT IDENTIFIER ::= {pkcs-5 14}
 *
 * PBMAC1-params ::= SEQUENCE {
 *   keyDerivationFunc AlgorithmIdentifier {{PBMAC1-KDFs}},
 *   messageAuthScheme AlgorithmIdentifier {{PBMAC1-MACs}}
 * }
 *
 * PBMAC1-KDFs ALGORITHM-IDENTIFIER ::=
 *   { {PBKDF2-params IDENTIFIED BY id-PBKDF2}, ... }
 *
 * PBMAC1-MACs ALGORITHM-IDENTIFIER ::= {
 *   {HMAC-SHA1 IDENTIFIED BY id-hmacWithSHA1} |
 *   {HMAC-SHA224 IDENTIFIED BY id-hmacWithSHA224} |
 *   {HMAC-SHA256 IDENTIFIED BY id-hmacWithSHA256} |
 *   {HMAC-SHA384 IDENTIFIED BY id-hmacWithSHA384} |
 *   {HMAC-SHA512 IDENTIFIED BY id-hmacWithSHA512} |
 *   {HMAC-SHA512/224 IDENTIFIED BY id-hmacWithSHA512-224} |
 *   {HMAC-SHA512/256 IDENTIFIED BY id-hmacWithSHA512-256}, ... }
 * </pre>
 *
 * @since 26
 */
public final class PBMAC1Parameters extends AlgorithmParametersSpi {

    static final ObjectIdentifier pkcs5PBKDF2_OID =
            ObjectIdentifier.of(KnownOIDs.PBKDF2);

    private static final ObjectIdentifier pkcs5PBMAC1_OID =
            ObjectIdentifier.of(KnownOIDs.PBMAC1);

    private String hmacAlgo;
    private byte[] salt;
    private int iterationCount;
    private int keyLength;
    private String kdfAlgo;

    public PBMAC1Parameters() {
        hmacAlgo = null;
        salt = null;
        iterationCount = 0;
        keyLength = 0;
        kdfAlgo = null;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {
        throw new InvalidParameterSpecException
                ("PBMAC1Parameters does not support AlgorithmParameterSpec");
    }

    @Override
    protected void engineInit(byte[] encoded) throws IOException {
        DerValue pBMAC1_params = new DerValue(encoded);
        if (pBMAC1_params.tag != DerValue.tag_Sequence) {
            throw new IOException("PBMAC1 parameter parsing error: "
                    + "not a sequence");
        }

        DerValue kdf = pBMAC1_params.data.getDerValue();

        // KDF info (keyDerivationFunc AlgorithmIdentifier)
        if (kdf.tag != DerValue.tag_Sequence) {
            throw new IOException("PBMAC1 parameter parsing error: "
                    + "not an ASN.1 SEQUENCE tag");
        }
        ObjectIdentifier OID = kdf.data.getOID();

        if (OID.equals(pkcs5PBKDF2_OID)) {
            // Parse PBKDF2 parameters
            DerValue pbkdf2Params = kdf.data.getDerValue();
            if (pbkdf2Params.tag != DerValue.tag_Sequence) {
                throw new IOException("PBKDF2 parameter parsing error: "
                        + "not a sequence");
            }
            
            // Parse salt
            this.salt = pbkdf2Params.data.getOctetString();
            
            // Parse iteration count
            this.iterationCount = pbkdf2Params.data.getInteger();
            
            // Parse optional key length
            if (pbkdf2Params.data.available() > 0) {
                DerValue val = pbkdf2Params.data.getDerValue();
                if (val.tag == DerValue.tag_Integer) {
                    this.keyLength = val.getInteger();
                    if (pbkdf2Params.data.available() > 0) {
                        val = pbkdf2Params.data.getDerValue();
                    }
                }
                // Parse optional PRF (default is HmacSHA1)
                if (val != null && val.tag == DerValue.tag_Sequence) {
                    ObjectIdentifier prfOID = val.data.getOID();
                    KnownOIDs prfKnown = KnownOIDs.findMatch(prfOID.toString());
                    if (prfKnown != null) {
                        this.kdfAlgo = prfKnown.stdName();
                    }
                }
            }
            
            if (this.kdfAlgo == null) {
                this.kdfAlgo = "HmacSHA1"; // Default PRF
            }
        } else {
            throw new IOException("PBMAC1 parameter parsing error: "
                    + "expecting the object identifier for PBKDF2");
        }

        if (kdf.data.available() != 0) {
            throw new IOException("PBMAC1 parameter parsing error: "
                    + "extra data for KDF");
        }

        // MAC info (messageAuthScheme AlgorithmIdentifier)
        DerValue mac = pBMAC1_params.data.getDerValue();
        ObjectIdentifier macOID = mac.data.getOID();
        KnownOIDs o = KnownOIDs.findMatch(macOID.toString());

        if (o == null || (!o.stdName().equals("HmacSHA1")
                && !o.stdName().equals("HmacSHA224")
                && !o.stdName().equals("HmacSHA256")
                && !o.stdName().equals("HmacSHA384")
                && !o.stdName().equals("HmacSHA512")
                && !o.stdName().equals("HmacSHA512/224")
                && !o.stdName().equals("HmacSHA512/256"))) {
            throw new IOException("PBMAC1 parameter parsing error: "
                    + "expecting the object identifier for a HmacSHA key "
                    + "derivation function");
        }
        hmacAlgo = o.stdName();

        if (mac.data.available() != 0) {
            throw new IOException("PBMAC1 parameter parsing error: "
                    + "extra data for MAC");
        }

        if (pBMAC1_params.data.available() != 0) {
            throw new IOException("PBMAC1 parameter parsing error: "
                    + "extra data");
        }
    }

    @Override
    protected void engineInit(byte[] encoded, String decodingMethod)
            throws IOException {
        engineInit(encoded);
    }

    @Override
    protected <T extends AlgorithmParameterSpec>
            T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        throw new InvalidParameterSpecException
                ("PBMAC1Parameters does not support AlgorithmParameterSpec");
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        DerOutputStream out = new DerOutputStream();

        // keyDerivationFunc AlgorithmIdentifier {{PBMAC1-KDFs}}
        DerOutputStream kdfOut = new DerOutputStream();
        kdfOut.putOID(pkcs5PBKDF2_OID);
        
        // PBKDF2 parameters
        DerOutputStream pbkdf2Out = new DerOutputStream();
        pbkdf2Out.putOctetString(salt);
        pbkdf2Out.putInteger(iterationCount);
        if (keyLength > 0) {
            pbkdf2Out.putInteger(keyLength);
        }
        // Add PRF if not default
        if (kdfAlgo != null && !kdfAlgo.equals("HmacSHA1")) {
            ObjectIdentifier prfOID = ObjectIdentifier.of(KnownOIDs.findMatch(kdfAlgo));
            DerOutputStream prfOut = new DerOutputStream();
            prfOut.putOID(prfOID);
            pbkdf2Out.write(DerValue.tag_Sequence, prfOut);
        }
        
        kdfOut.write(DerValue.tag_Sequence, pbkdf2Out);
        out.write(DerValue.tag_Sequence, kdfOut);

        // messageAuthScheme AlgorithmIdentifier {{PBMAC1-MACs}}
        ObjectIdentifier hmacOID = ObjectIdentifier.of(KnownOIDs.findMatch(hmacAlgo));
        DerOutputStream hmacOut = new DerOutputStream();
        hmacOut.putOID(hmacOID);
        out.write(DerValue.tag_Sequence, hmacOut);

        return new DerOutputStream().write(DerValue.tag_Sequence, out).toByteArray();
    }

    @Override
    protected byte[] engineGetEncoded(String encodingMethod)
            throws IOException {
        return engineGetEncoded();
    }

    @Override
    protected String engineToString() {
        return "PBMAC1 Parameters: salt=" + (salt != null ? salt.length : 0) + " bytes, " +
               "iterationCount=" + iterationCount + ", " +
               "keyLength=" + keyLength + ", " +
               "kdfAlgo=" + kdfAlgo + ", " +
               "MAC=" + hmacAlgo;
    }

    byte[] getSalt() {
        return salt != null ? salt.clone() : null;
    }

    int getIterationCount() {
        return iterationCount;
    }

    int getKeyLength() {
        return keyLength;
    }

    String getKdfAlgo() {
        return kdfAlgo;
    }

    String getHmacAlgo() {
        return hmacAlgo;
    }
}

// Made with Bob
