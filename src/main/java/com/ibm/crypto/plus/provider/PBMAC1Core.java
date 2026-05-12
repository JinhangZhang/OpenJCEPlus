/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.HMAC;
import com.ibm.crypto.plus.provider.base.PBKDF;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * This class implements the PBMAC1 algorithm as defined in PKCS#5 v2.1.
 * PBMAC1 combines PBKDF2 for key derivation with HMAC for message authentication.
 *
 * @since 26
 */
abstract class PBMAC1Core extends MacSpi {

    private final String prfAlgo;
    private OpenJCEPlusProvider provider = null;
    private HMAC hmac = null;
    private byte[] derivedKey = null;

    PBMAC1Core(OpenJCEPlusProvider provider, String prfAlgo, String ockDigestAlgo) {
        try {
            this.provider = provider;
            this.prfAlgo = prfAlgo;
            this.hmac = HMAC.getInstance(ockDigestAlgo, provider);
        } catch (Exception e) {
            throw provider.providerException("Failure in PBMAC1Core", e);
        }
    }

    @Override
    protected byte[] engineDoFinal() {
        try {
            return hmac.doFinal();
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        }
    }

    @Override
    protected int engineGetMacLength() {
        try {
            return hmac.getMacLength();
        } catch (Exception e) {
            throw provider.providerException("Failure in engineGetMacLength", e);
        }
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        
        if (params == null) {
            throw new InvalidAlgorithmParameterException(
                    "PBMAC1 requires PBEParameterSpec");
        }

        if (!(params instanceof PBEParameterSpec pbeParams)) {
            throw new InvalidAlgorithmParameterException(
                    "PBMAC1 requires PBEParameterSpec");
        }

        char[] password = null;
        if (key instanceof javax.crypto.interfaces.PBEKey pbeKey) {
            password = pbeKey.getPassword();
        } else if (key instanceof SecretKey) {
            byte[] passwdBytes = key.getEncoded();
            if (passwdBytes == null) {
                throw new InvalidKeyException("Missing key data");
            }
            password = new char[passwdBytes.length];
            for (int i = 0; i < passwdBytes.length; i++) {
                password[i] = (char) (passwdBytes[i] & 0x7f);
            }
            Arrays.fill(passwdBytes, (byte) 0x00);
        } else {
            throw new InvalidKeyException("SecretKey of PBE type required");
        }

        byte[] salt = pbeParams.getSalt();
        int iterationCount = pbeParams.getIterationCount();
        
        if (salt == null) {
            throw new InvalidAlgorithmParameterException("Salt not found");
        }
        if (iterationCount <= 0) {
            throw new InvalidAlgorithmParameterException(
                    "IterationCount must be a positive number");
        }

        // Derive key using PBKDF2
        byte[] passwordBytes = new byte[password.length];
        for (int i = 0; i < password.length; i++) {
            passwordBytes[i] = (byte) password[i];
        }

        try {
            // Get the MAC length to determine key length
            int keyLength = engineGetMacLength();
            
            // Derive key using PBKDF2
            derivedKey = PBKDF.PBKDF2derive(prfAlgo, passwordBytes, salt, 
                    iterationCount, keyLength, provider);
            
            // Initialize HMAC with derived key
            hmac.initialize(derivedKey);
        } catch (Exception e) {
            throw new InvalidKeyException("Cannot derive key", e);
        } finally {
            Arrays.fill(passwordBytes, (byte) 0x00);
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    @Override
    protected void engineReset() {
        try {
            hmac.reset();
        } catch (Exception e) {
            throw provider.providerException("Failure in engineReset", e);
        }
    }

    @Override
    protected void engineUpdate(byte input) {
        byte[] singleByte = new byte[1];
        singleByte[0] = input;
        engineUpdate(singleByte, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int length) {
        try {
            this.hmac.update(input, offset, length);
        } catch (Exception e) {
            throw provider.providerException("Failure in engineUpdate", e);
        }
    }

    // Nested static classes for different HMAC algorithms
    public static final class HmacSHA1 extends PBMAC1Core {
        public HmacSHA1(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA1", "SHA1");
        }
    }

    public static final class HmacSHA224 extends PBMAC1Core {
        public HmacSHA224(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA224", "SHA224");
        }
    }

    public static final class HmacSHA256 extends PBMAC1Core {
        public HmacSHA256(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA256", "SHA256");
        }
    }

    public static final class HmacSHA384 extends PBMAC1Core {
        public HmacSHA384(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA384", "SHA384");
        }
    }

    public static final class HmacSHA512 extends PBMAC1Core {
        public HmacSHA512(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA512", "SHA512");
        }
    }

    public static final class HmacSHA512_224 extends PBMAC1Core {
        public HmacSHA512_224(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA512/224", "SHA512-224");
        }
    }

    public static final class HmacSHA512_256 extends PBMAC1Core {
        public HmacSHA512_256(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA512/256", "SHA512-256");
        }
    }
}

// Made with Bob
