/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.util.Locale;

final class PQCKeyEncoding {

    enum Format {
        SEED,
        EXPANDED_KEY,
        BOTH
    }

    private PQCKeyEncoding() {}

    static Format getPreferred(String algorithm) {
        String property =
                System.getProperty("jdk." + algorithm + ".pkcs8.encoding");

        if (property == null) {
            return Format.EXPANDED_KEY;
        }

        return switch (property.toLowerCase(Locale.ROOT)) {
            case "seed" -> Format.SEED;
            case "expandedkey" -> Format.EXPANDED_KEY;
            case "both" -> Format.BOTH;
            default -> throw new IllegalArgumentException(
                    "Unknown format: " + property);
        };
    }
}
