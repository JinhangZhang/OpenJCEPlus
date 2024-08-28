/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.openjceplusfips;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class TestECDHKeyAgreementParamValidation extends BaseTestECDHKeyAgreement{

    public TestECDH() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    @BeforeAll
    public static void init() throws Exception {
        if (java.security.Security.getProvider("OpenJCEPlus") != null) {
            java.security.Security.removeProvider("OpenJCEPlus");
        }
        insertProvider("OpenJCEPlusFIPS", "com.ibm.crypto.plus.provider.OpenJCEPlusFIPS", 1);
    }
    
}
