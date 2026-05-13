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
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.KnownOIDs;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

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
 *   messageAuthScheme AlgorithmIdentifier {{PBMAC1-MACs}} }
 *
 * PBMAC1-KDFs ALGORITHM-IDENTIFIER ::=
 *   { {PBKDF2-params IDENTIFIED BY id-PBKDF2}, ... }
 *
 * PBMAC1-MACs ALGORITHM-IDENTIFIER ::= { ... }
 *
 * -- PBKDF2
 *
 * See PBKDF2Parameters.
 *
 * </pre>
 *
 * This class wraps the upstream sun.security.pkcs12.PBMAC1Parameters logic
 * in an AlgorithmParametersSpi for provider registration.
 *
 * @since 26
 */
public final class PBMAC1Parameters extends AlgorithmParametersSpi {

    static final ObjectIdentifier pkcs5PBKDF2_OID =
            ObjectIdentifier.of(KnownOIDs.PBKDF2);

    private String hmacAlgo;
    private PBKDF2Parameters kdfParams;

    public PBMAC1Parameters() {
        // Initialize to null
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {
        throw new InvalidParameterSpecException
                ("PBMAC1Parameters does not support AlgorithmParameterSpec");
    }

    @Override
    protected void engineInit(byte[] encoded) throws IOException {
        // This follows the exact upstream sun.security.pkcs12.PBMAC1Parameters logic
        DerValue pBMAC1_params = new DerValue(encoded);
        if (pBMAC1_params.tag != DerValue.tag_Sequence) {
            throw new IOException("PBMAC1 parameter parsing error: "
                    + "not an ASN.1 SEQUENCE tag");
        }
        DerValue[] info = new DerInputStream(pBMAC1_params.toByteArray())
                .getSequence(2);
        if (info.length != 2) {
            throw new IOException("PBMAC1 parameter parsing error: "
                + "expected length not 2");
        }
        
        // Parse MAC algorithm (info[1]) first, matching upstream order
        ObjectIdentifier OID = info[1].data.getOID();
        KnownOIDs o = KnownOIDs.findMatch(OID.toString());
        if (o == null || (!o.stdName().equals("HmacSHA1") &&
                !o.stdName().equals("HmacSHA224") &&
                !o.stdName().equals("HmacSHA256") &&
                !o.stdName().equals("HmacSHA384") &&
                !o.stdName().equals("HmacSHA512") &&
                !o.stdName().equals("HmacSHA512/224") &&
                !o.stdName().equals("HmacSHA512/256"))) {
            throw new IOException("PBMAC1 parameter parsing error: "
                    + "expecting the object identifier for a HmacSHA key "
                    + "derivation function");
        }
        // Hmac function used to compute the MAC
        this.hmacAlgo = o.stdName();

        // Parse KDF (info[0])
        DerValue kdf = info[0];

        if (!pkcs5PBKDF2_OID.equals(kdf.data.getOID())) {
            throw new IOException("PBKDF2 parameter parsing error: "
                + "expecting the object identifier for PBKDF2");
        }
        if (kdf.tag != DerValue.tag_Sequence) {
            throw new IOException("PBKDF2 parameter parsing error: "
                + "not an ASN.1 SEQUENCE tag");
        }
        DerValue pBKDF2_params = kdf.data.getDerValue();

        this.kdfParams = new PBKDF2Parameters(pBKDF2_params);
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
        // Encode PBMAC1 parameters matching upstream logic
        DerOutputStream out = new DerOutputStream();

        // keyDerivationFunc AlgorithmIdentifier {{PBMAC1-KDFs}}
        out.writeBytes(PBKDF2Parameters.encode(
                kdfParams.getSalt(),
                kdfParams.getIterationCount(),
                kdfParams.getKeyLength(),
                kdfParams.getPrfAlgo()));

        // messageAuthScheme AlgorithmIdentifier {{PBMAC1-MACs}}
        try {
            out.write(AlgorithmId.get(hmacAlgo));
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("Cannot encode PBMAC1 parameters", e);
        }
        
        return new DerOutputStream().write(DerValue.tag_Sequence, out)
                .toByteArray();
    }

    @Override
    protected byte[] engineGetEncoded(String encodingMethod)
            throws IOException {
        return engineGetEncoded();
    }

    @Override
    protected String engineToString() {
        return "PBMAC1 Parameters: " +
               "kdfParams=" + (kdfParams != null ?
                   "salt=" + kdfParams.getSalt().length + " bytes, " +
                   "iterationCount=" + kdfParams.getIterationCount() + ", " +
                   "keyLength=" + kdfParams.getKeyLength() + ", " +
                   "prfAlgo=" + kdfParams.getPrfAlgo() : "null") + ", " +
               "MAC=" + hmacAlgo;
    }

    PBKDF2Parameters getKdfParams() {
        return kdfParams;
    }

    String getHmacAlgo() {
        return hmacAlgo;
    }
}

// Made with Bob
