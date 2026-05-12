/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * This class implements the PBMAC1 algorithm as defined in PKCS#5 v2.1.
 * PBMAC1 combines PBKDF2 for key derivation with HMAC for message authentication.
 *
 * This implementation extends HmacCore and overrides only engineInit to add
 * PBKDF2 key derivation before delegating to the parent HMAC implementation.
 * It uses PBKDF2Core (SecretKeyFactory) for key derivation, following the
 * upstream OpenJDK implementation pattern.
 *
 * @since 26
 */
abstract class PBMAC1Core extends HmacCore {

    // NOTE: this class inherits the Cloneable interface from HmacCore
    // Need to override clone() if mutable fields are added.
    private final String kdfAlgo;
    private final String hashAlgo;
    private final int blockLength; // in octets
    private final OpenJCEPlusProvider provider;

    PBMAC1Core(OpenJCEPlusProvider provider, String kdfAlgo, String hashAlgo, int blockLength) {
        super(provider, hashAlgo, blockLength);
        this.provider = provider;
        this.kdfAlgo = kdfAlgo;
        this.hashAlgo = hashAlgo;
        this.blockLength = blockLength;
    }

    private static PBKDF2Core getKDFImpl(OpenJCEPlusProvider provider, String algo) {
        return switch (algo) {
            case "HmacSHA1" -> new PBKDF2Core.HmacSHA1(provider);
            case "HmacSHA224" -> new PBKDF2Core.HmacSHA224(provider);
            case "HmacSHA256" -> new PBKDF2Core.HmacSHA256(provider);
            case "HmacSHA384" -> new PBKDF2Core.HmacSHA384(provider);
            case "HmacSHA512" -> new PBKDF2Core.HmacSHA512(provider);
            case "HmacSHA512/224" -> new PBKDF2Core.HmacSHA512_224(provider);
            case "HmacSHA512/256" -> new PBKDF2Core.HmacSHA512_256(provider);
            default -> throw new RuntimeException("No MAC implementation for " + algo);
        };
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        
        char[] passwdChars;
        byte[] salt = null;
        int iCount = 0;
        
        if (key instanceof javax.crypto.interfaces.PBEKey pbeKey) {
            passwdChars = pbeKey.getPassword();
            salt = pbeKey.getSalt(); // maybe null if unspecified
            iCount = pbeKey.getIterationCount(); // maybe 0 if unspecified
        } else if (key instanceof SecretKey) {
            byte[] passwdBytes = key.getEncoded();
            if (passwdBytes == null) {
                throw new InvalidKeyException("Missing password");
            }
            passwdChars = new char[passwdBytes.length];
            for (int i = 0; i < passwdChars.length; i++) {
                passwdChars[i] = (char) (passwdBytes[i] & 0x7f);
            }
            Arrays.fill(passwdBytes, (byte) 0);
        } else {
            throw new InvalidKeyException("SecretKey of PBE type required");
        }

        // Make sure the parameter values are consistent
        if (salt == null) {
            throw new InvalidAlgorithmParameterException(
                    "PBEParameterSpec required for salt and iteration count");
        }
        if (iCount == 0) {
            throw new InvalidAlgorithmParameterException(
                    "PBEParameterSpec required for salt and iteration count");
        } else if (!(params instanceof PBEParameterSpec)) {
            throw new InvalidAlgorithmParameterException(
                    "PBEParameterSpec type required");
        } else {
            PBEParameterSpec pbeParams = (PBEParameterSpec) params;
            // Make sure the parameter values are consistent
            if (salt != null) {
                if (!Arrays.equals(salt, pbeParams.getSalt())) {
                    throw new InvalidAlgorithmParameterException(
                            "Inconsistent value of salt between key and params");
                }
            } else {
                salt = pbeParams.getSalt();
            }
            if (iCount != 0) {
                if (iCount != pbeParams.getIterationCount()) {
                    throw new InvalidAlgorithmParameterException(
                            "Different iteration count between key and params");
                }
            } else {
                iCount = pbeParams.getIterationCount();
            }
        }
        
        // For salt; just require the minimum salt length to be 8-byte
        // which is what PKCS#5 recommends and openssl does.
        if (salt.length < 8) {
            throw new InvalidAlgorithmParameterException(
                    "Salt must be at least 8 bytes long");
        }
        if (iCount <= 0) {
            throw new InvalidAlgorithmParameterException(
                    "IterationCount must be a positive number");
        }

        PBEKeySpec pbeSpec = new PBEKeySpec(passwdChars, salt, iCount, blockLength);
        // password char[] was cloned in PBEKeySpec constructor,
        // so we can zero it out here
        Arrays.fill(passwdChars, '\0');

        PBKDF2Core kdf = null;
        SecretKey s = null;
        byte[] derivedKey = null;
        try {
            kdf = getKDFImpl(provider, kdfAlgo);
            s = kdf.engineGenerateSecret(pbeSpec);
            derivedKey = s.getEncoded();
            SecretKey cipherKey = new javax.crypto.spec.SecretKeySpec(derivedKey, "PBMAC1");
            super.engineInit(cipherKey, null);
        } catch (InvalidKeySpecException ikse) {
            throw new InvalidKeyException("Cannot construct PBE key", ikse);
        } finally {
            if (derivedKey != null) {
                Arrays.fill(derivedKey, (byte) 0);
            }
            if (s != null) {
                try {
                    s.destroy();
                } catch (Exception e) {
                    // Ignore
                }
            }
            pbeSpec.clearPassword();
        }
    }

    // Nested static classes for different HMAC algorithms
    public static final class HmacSHA1 extends PBMAC1Core {
        public HmacSHA1(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA1", "SHA1", 64);
        }
    }

    public static final class HmacSHA224 extends PBMAC1Core {
        public HmacSHA224(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA224", "SHA224", 64);
        }
    }

    public static final class HmacSHA256 extends PBMAC1Core {
        public HmacSHA256(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA256", "SHA256", 64);
        }
    }

    public static final class HmacSHA384 extends PBMAC1Core {
        public HmacSHA384(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA384", "SHA384", 128);
        }
    }

    public static final class HmacSHA512 extends PBMAC1Core {
        public HmacSHA512(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA512", "SHA512", 128);
        }
    }

    public static final class HmacSHA512_224 extends PBMAC1Core {
        public HmacSHA512_224(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA512/224", "SHA512-224", 128);
        }
    }

    public static final class HmacSHA512_256 extends PBMAC1Core {
        public HmacSHA512_256(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA512/256", "SHA512-256", 128);
        }
    }
}
