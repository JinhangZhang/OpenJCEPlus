/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.openjceplus;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class TestECDHKeyAgreementParamValidation extends BaseTestECDHKeyAgreement{

    @BeforeAll
    public static void init() throws Exception {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);

        if (java.security.Security.getProvider("OpenJCEPlusFIPS") != null) {
            java.security.Security.removeProvider("OpenJCEPlusFIPS");
        }
        insertProvider("OpenJCEPlus", "com.ibm.crypto.plus.provider.OpenJCEPlus", 1);
    }
    
}
