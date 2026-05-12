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
        DerValue[] info = new DerInputStream(encoded).getSequence(2);
        if (info.length != 2) {
            throw new IOException("PBMAC1 parameter parsing error: "
                    + "expected length not 2");
        }
        
        DerValue kdf = info[0];
        if (kdf.tag != DerValue.tag_Sequence) {
            throw new IOException("PBKDF2 parameter parsing error: "
                    + "not an ASN.1 SEQUENCE tag");
        }
        
        ObjectIdentifier OID = kdf.data.getOID();
        if (!OID.equals(pkcs5PBKDF2_OID)) {
            throw new IOException("PBKDF2 parameter parsing error: "
                    + "not an ASN.1 SEQUENCE tag");
        }
        
        DerValue pBKDF2_params = kdf.data.getDerValue();
        this.kdfParams = new PBKDF2Parameters(pBKDF2_params);
        
        // Hmac function used to compute the MAC
        ObjectIdentifier macOID = info[1].data.getOID();
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
        this.hmacAlgo = o.stdName();
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
        
        // PBKDF2 parameters - use PBKDF2Parameters.encode()
        byte[] pbkdf2Encoded = PBKDF2Parameters.encode(
                kdfParams.getSalt(),
                kdfParams.getIterationCount(),
                kdfParams.getKeyLength(),
                kdfParams.getPrfAlgo());
        kdfOut.write(pbkdf2Encoded);
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
