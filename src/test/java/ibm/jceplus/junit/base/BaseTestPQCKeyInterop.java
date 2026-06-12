/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import ibm.jceplus.junit.openjceplus.Utils;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

public class BaseTestPQCKeyInterop extends BaseTestJunit5Interop {


    protected KeyPairGenerator keyPairGenPlus;
    protected KeyFactory keyFactoryPlus;
    protected KeyPairGenerator keyPairGenInterop;
    protected KeyFactory keyFactoryInterop;

    byte[] origMsg = "this is the original message to be signed".getBytes();

    private static final String RFC9881_ML_DSA_44_PRIVATE_KEY_SEED = """
            -----BEGIN PRIVATE KEY-----
            MDQCAQAwCwYJYIZIAWUDBAMRBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4f
            -----END PRIVATE KEY-----
            """;;

    private static final String RFC9881_ML_DSA_44_PRIVATE_KEY_EXPANDED = """
            -----BEGIN PRIVATE KEY-----
            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
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9881_ML_DSA_44_PRIVATE_KEY_BOTH = """
            -----BEGIN PRIVATE KEY-----
            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
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9881_ML_DSA_44_PUBLIC_KEY = """
            -----BEGIN PUBLIC KEY-----
            MIIFMjALBglghkgBZQMEAxEDggUhANeytHJUquDbReeTDUqY0sl9jxOX0Xidr6Fw
            JLMW6b7JT8mUbULxm3mnQTu6oz5xSctC7VEVaTrAQfrLmIretf4OHYYxGEmVtZLD
            l9IpTi4U+QqkFLo4JomaxD9MzKy8JumoMrlRGNXLQzy++WYLABOOCBf2HnYsonTD
            atVU6yKqwRYuSrAay6HjjE79j4C2WzM9D3LlXf5xzpweu5iJ58VhBsD9c4A6Kuz+
            r97XqjyyztpU0SvYzTanjPl1lDtHq9JeiArEUuV0LtHo0agq+oblkMdYwVrk0oQN
            kryhpQkPQElll/yn2LlRPxob2m6VCqqY3kZ1B9Sk9aTwWZIWWCw1cvYu2okFqzWB
            ZwxKAnd6M+DKcpX9j0/20aCjp2g9ZfX19/xg2gI+gmxfkhRMAvfRuhB1mHVT6pNn
            /NdtmQt/qZzUWv24g21D5Fn1GH3wWEeXCaAepoNZNfpwRgmQzT3BukAbqUurHd5B
            rGerMxncrKBgSNTE7vJ+4TqcF9BTj0MPLWQtwkFWYN54h32NirxyUjl4wELkKF9D
            GYRsRBJiQpdoRMEOVWuiFbWnGeWdDGsqltOYWQcf3MLN51JKe+2uVOhbMY6FTo/i
            svPt+slxkSgnCq/R5QRMOk/a/Z/zH5B4S46ORZYUSg2vWGUR09mWK56pWvGXtOX8
            YPKx7RXeOlvvX4m9x52RBR2bKBbnT6VFMe/cHL501EiFf0drzVjyHAtlOzt2pOB2
            plWaMCcYVVzGP3SFmqurkl8COGHKjND3utsocfZ9VTJtdFETWtRfShumkRj7ssij
            DuyTku8/l3Bmya3VxxDMZHsVFNIX2VjHAXw+kP0gwE5nS5BIbpNwoxoAHTL0c5ee
            SQZ0nn5Hf6C3RQj4pfI3gxK4PCW9OIygsP/3R4uvQrcWZ+2qyXxGsSlkPlhuWwVa
            DCEZRtTzbmdb7Vhg+gQqMV2YJhZNapI3w1pfv0lUkKW9TfJIuVxKrneEtgVnMWas
            QkW1tLCCoJ6TI+YvIHjFt2eDRG3v1zatOjcC1JsImESQCmGDM5e8RBmzDXqXoLOH
            wZEUdMTUG1PjKpd6y28Op122W7OeWecB52lX3vby1EVZwxp3EitSBOO1whnxaIsU
            7QvAuAGz5ugtzUPpwOn0F0TNmBW9G8iCDYuxI/BPrNGxtoXdWisbjbvz7ZM2cPCV
            oYC08ZLQixC4+rvfzCskUY4y7qCl4MkEyoRHgAg/OwzS0Li2r2e8NVuUlAJdx7Cn
            j6gOOi2/61EyiFHWB4GY6Uk2Ua54fsAlH5Irow6fUd9iptcnhM890gU5MXbfoySl
            Er2Ulwo23TSlFKhnkfDrNvAUWwmrZGUbSgMTsplhGiocSIkWJ1mHaKMRQGC6RENI
            bfUVIqHOiLMJhcIW+ObtF43VZ7MEoNTK+6iCooNC8XqaomrljbYwCD0sNY/fVmw/
            XWKkKFZ7yeqM6VyqDzVHSwv6jzOaJQq0388gg76O77wQVeGP4VNw7ssmBWbYP/Br
            IRquxDyim1TM0A+IFaJGXvC0ZRXMfkHzEk8J7/9zkwmrWLKaFFmgC85QOOk4yWeP
            cusOTuX9quZtn4Vz/Jf8QrSVn0v4th14Qz6GsDNdbpGRxNi/SHs5BcEIz9asJLDO
            t9y3z1H4TQ7Wh7lerrHFM8BvDZcCPZKnCCWDe1m6bLfU5WsKh8IDhiro8xW6WSXo
            7e+meTaaIgJ2YVHxapZfn4Hs52zAcLVYaeTbl4TPBcgwsyQsgxI=
            -----END PUBLIC KEY-----
            """;

    private static final String RFC9881_ML_DSA_65_PRIVATE_KEY_SEED = """
            -----BEGIN PRIVATE KEY-----
            MDQCAQAwCwYJYIZIAWUDBAMSBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4f
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9881_ML_DSA_65_PRIVATE_KEY_EXPANDED = """
            -----BEGIN PRIVATE KEY-----
            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
            v++Sr2yhR7EyRNbIkvyO8iOrP0P5JML0Zgl+6A==
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9881_ML_DSA_65_PRIVATE_KEY_BOTH = """
            -----BEGIN PRIVATE KEY-----
            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
            1siS/I7yI6s/Q/kkwvRmCX7o
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9881_ML_DSA_65_PUBLIC_KEY = """
            -----BEGIN PUBLIC KEY-----
            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
            HgLy6ERP
            -----END PUBLIC KEY-----
            """;

    private static final String RFC9881_ML_DSA_87_PRIVATE_KEY_SEED ="""
            -----BEGIN PRIVATE KEY-----
            MDQCAQAwCwYJYIZIAWUDBAMTBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4f
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9881_ML_DSA_87_PRIVATE_KEY_EXPANDED ="""
            -----BEGIN PRIVATE KEY-----
            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
            v+h/H5X/wulvxVllZ+lDZN+qbZ1abrma5N30JA==
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9881_ML_DSA_87_PRIVATE_KEY_BOTH = """
            -----BEGIN PRIVATE KEY-----
            MIITXgIBADALBglghkgBZQMEAxMEghNKMIITRgQgAAECAwQFBgcICQoLDA0ODxAR
            EhMUFRYXGBkaGxwdHh8EghMgl5K87C8kMGhqgvzPPC9f9mXncderQbkCWM+n6Q7J
            cSTY6e5OkKFsYC9eybw4UX3DDjKdWrJ2c72F9MmwMA93Y4mIZ1C1fCTbP8AS5h7e
            WXUzNzdPpxJJkVSa8kNJbQY3yzvgWllII1v3mHX4ltj+DKswyElI201jFaqvFgrG
            JDZkIgFIFhEJESyUAokiRSxiuEUARSoIlnCQEm4Uk3DURhCERFFYlpEMqSmCskHJ
            CHHEKGgElolIQIWbIm0cKGRZEkGcuJGEBIlEkAXLNGKghpBAJpIgmSkTBWlcNGik
            Mo4ZJpJZRhAJpEkjQk0SNmFYEGUBKJAaM0yZhjHTokkJgiVDFCjAOIEDFU1bKIYI
            h0gjMVKUIiXDwE2kmCGYQCDRQobLQHBbsHGclizBEgZTRgkMRQIURm6RtCFUsIzk
            RkKaIIwBISUTQQVaQCITyQygGEBSwjDLNCxLyGgbpGBJhIRjMClKoGlbgATSOAoU
            JkziskSLohEkRknEFFILQnEDshCSKIABJIjjCBEKBSgZxIEAICLcRGhCEiJEACrJ
            JmoMhzHgwESZFIQYNg0RN0IiGIxjspEMmAihoAEIkkQEEyRcmHGChHGEMlJRsDGc
            Qi4aqCgCCJEBwIkLxwWKJGUiwmRMiJFcgmgTpWRQIIYhBAKRlERIIjAiOUoCmIQJ
            oogZGSlESIwilQyhBHIEh3ASIRBCBoQbSYWJBkrTNgjbwEBYtlEMpwmMJGGZkGSM
            wpBbJJAQo0kDJWFDMooRmETIsiAEOEEQRywZxkQcJSwEiDDZRmmbIAAbRoJapIBb
            oEkYkCUAJoALwjFaQHJUxiDBsDEksU0QlSgUAAqgyE1UoogjmIFgkAQCFiwTIUCR
            ho0IwpGRFCbQtAwJxmBRRC4EESYAKRGTwghjpDEiACjBFAgMQCxBFAacIHJUIgaL
            CE2hSGkQMEEcKElEGI7MlkjZQlAbBkkMRYgjBA0gMC4jhSwUBzBAtoVMwCBEhiAZ
            AGxUAkjMiGxZBjJJFIQEx1ATSSjkBgnTxhDIKEwjOURSpGTMqElEODIKiYQANCwi
            hY0QMQkJMmUciYxAQCkhhQAJoW2EwGTiAi1IBEASCY7gQi6TRAgSEGoBhAWSMIrL
            NI6iJi5chhELNQgYEAACNCYkI4nRhAAkRmATskkkKEYYAnGgOJCJFETTli2jGEAj
            JyHAGFBDyARBQo1cJkFEom1IEg5AMiULFIIKSC7LgogDo2AbJSaMuCAksIWYBCEI
            pyyDOGRUMokBBAEjSYQClWnRpE0TpAyRRg1hlICQOEVcxlABFyBTxiibGBBBEmiQ
            EiHAEIRCFpJTgimBJknYpAWaJiQkAyngQCbSAkgRJGgRmYmYFIXJIA1QEowcCBAC
            EAAAlSjBKJBZtIXTFGUKQG4RKWUYwkwhNGXYMGkQMFIZMWaMGIrIwAhMmDCjpiBB
            FiIYBS4iJSpkuCUKswFjIIQJgAkZKA4CEQGjlBHjmGxYICEJQRBgNiIIBnESwoVa
            oIXAxoRcOAbLtmkUhIRTIoKhpkDMhgDEJiKgqAiYNHLUIEFDxJBIFmgbFlIaNwJQ
            IEJISIogEUHiAGzAwgwUBkkRMU0ZBgqJRgkbgWVEyACCBnAAFnLMJFCKQomclpBk
            KHCSsmiYJmJhlEDBFonYQmQaIU5ikGQhyCSLKG1cQpKgxk0MhYDMiE3UQo1CNIoL
            BFHDJoYkJYESNQagRATIlIFbtDEcCAZcJAgDJ2ogwiXhgJAZtG2jRgxLGGBQxiwb
            ki0RFQSiAAQhSC7YFgbSEIqDoiUIMQ0JOFHZSEkLFkwjMiUZGQJKRAnRsiELgywj
            JYWTFoVEoEQbg1ACInJLBICbFGUhk2AYEwrZRg0iRWHItEChQi0CuAkAFESbthEL
            l4xAEEqCFGrakAUcAo4MGXKjtI0kMFARhwlkxijkGJKYtGxhFlFARg4cMkjaIFGI
            NoojsSGCkCgaFTLiGGGSBI4TtpATE2jJhGhMQG0LMwCBRk3SOAwEloGkiFACkIUi
            sATTpHHSgBDKlkBRpkGkhCjgCFILMIzSOAoMKVHDggnKIJHYNpKjpiiSQiKiFgEa
            NIY32aZZFpiB7CHPSBGGnR1/E58FN+lvEYRYVAX9F4CK8eBiOdOzTlrKi/E2lne0
            R6xxisR9hQxNd7C+MdyfUI45ePJCdKsBhfcnq9/1n0SQNxvwRhDjZOZOyHXvnSDc
            lAd+HhZjJ6h5uKtRYWCyo/d0N7mzzH0Xrq3chNtidGo1rAlveC9ip/AaptZpPe7J
            CyPGaYWgIwfgocrlmKZzJNug9S8iQyJ16TJXBlw7fl4c/h39TQ3wht8hJDQUotJ+
            ICMKgpvk60yCwW0194sOXhmDMuAAdLtkYS+rF9TIlxy2jl7asDafEVezRpq9g4Ti
            2VU/G3jnhuHunQuY05+DzOzzfR69Op1jrsdmFkoQFxpP2MY9rxgsQhJYxfUpqlXL
            frri4WUjFeH3Hop0ExQQ0DJH7eEdNNuR9vCKokeP14lnnASUn3G8AXHgfjqLtXU9
            u9qkEaY1CrRu77+G/FUcKe/kzddmHVz2w9si0M7d5ZmFRFnZfyDfdFW981ahmND3
            6200ER/JQLJcBUO3iO3anSaBDqw9bMnFEyfCz4Poh9QInhlpXhGt2Df29EDMNg+T
            8y/uipZjcSxrvTjISre1SCPsNj635C61n8H85g+9VTB7Pshf2drzIG17SzkX8ci3
            qS48Z9iYgP3y5H9aDJlFldsXCvQbq/WiW03BxC3WqdsnHnZN4vsBWkmoUMeRm+Rw
            BqM24uMl/eU6xZlVTQp95O9F7EDDnWuv8xG+7nXYngKtMfS+S9IK6RlPXt3apmUH
            dhFunycPd3FK16joms73S3/32NvsJ/gCCphSR+LNrO9IlKTWi6N8qRLWvnNQHJlR
            geW3dyM1CzYx2jcA4T/TZuExvwazbrawNFCTIJ8Ke+/64f3YdbAGh8EWPDU9fSrJ
            CTezTpeOkvghrclmIgLs6JoX57tlrhfYO5DbvmpQGk4TRb7k5aW1OvLluj0e8/Tg
            Wt8LOkzy5TA2D+5kkpkCtXH2/S4wVlKkywEPefgV4Y8ru4zIn6b8dvd8ieKTzxda
            CxlYAP5y0szdfXXlvZC8asQ11qRA74UumhyMU94DvxkzZdc1qvKcUWKmF+Nk5/lE
            Fo0PtI/vQFWPRUKXzD3VCGYs8j+4jhlUqkXRxeEVvMNvBbPgmNVVIg9AviYps0UH
            uEZMVMJ7Xex42o8iZQUUeXr4aiUSvLfikjN5721zwTcAbBs49R43+TWF4pBBo+Tj
            r0YAfOE7i197F9XWXX1WaOQnvL5+wdfECMBUpIwa55e/may8jSYHUik1/WZep4It
            kw8j6r/3g7sjaXVp4gS5QxQeAMCIEJVr4FJTZdurVO1Iy3aWTM31y9Ou5ygtSgAA
            0nhNe4+rFrL38NUiVzKx77xOsc/t60P955tp7MD76qHmtAcoZzvUsumKDUqPAvhT
            lQcw8o016xL8x5douOGOS9oOWKMxovcdfMwtRRsyscZcMSrPR+5ROyGVTEHADIc4
            cu6UzxT0YDdCU2H0vbVIIfcRRgzrrowHUIqSGfiPpr7apnju1QGUShaub3tbt6Lh
            41fnDXuYRhosccsPp2LWrZgkCB038pL9S+i4TDYRDcdENgIBvuvgvWydBehpJW0v
            8/mVF7fv0qM3dAVstWcWdai0kun18mIOuO+TgdPR3xmTi3tf+qxZvIEQ+oe6jXo9
            AWX45B3Q+ATxG53tDzUqWXg10GMHqODG700hkEM54c9FiSOj6J4CXZRTRzZsAvPd
            Y2jU5H6F09KpcFvVeWGFLlpXn5OxxRTFOfSeoRY6Kkk7Dvy0f0dI9qmeEL9weCgu
            Ss4YE24qiz7go4Dc07PvPmXhuBVyidYkZ61Ii6A5Ky6Qoe3ty9yTHcFymMzvdmRc
            fTMKBcLOQPibhUaPNXohd1HhVGMTBOxOBLtFs2eJCcdK9RzjcDZNj09+seYeACh0
            KcmWHegyLKmiYpsTCdgA6SvB3FBV3MeX8zhm6wz9jUkCUNSP/KgCL0kpDi1TdhYv
            uqmC0WRTyCWzX2UVY16pK+pyNnuqVN4/nq6mlUKoGkEn9xy6olfzJP7+8U8I+9Za
            BJzS+zYllKjiP/GiYX21sVj28Bz1CrDtlcbnCYQRZBCLBuG0CrCrEcQIMB09nY6m
            npaKlgCz0X84ARzigHTiwuEL9hl8YC2NDOfTo+8tiWI7yfEuozh5HpJmu4zgKxJM
            bHkpuuppMkQJhFSggOt1I+E7sbfFtndfq6urvpB1/laHqkUTl7uc/M0FEkPpv1rv
            JAYtM13l/OJOndveEZEFLYDDbfn4Q0hy8nftT1oc6OvTuWCCSk5PEAGwTLaF+b7k
            0N2wxXFZisICGmYG/SM0XG+7hPDOBf5Sc0Uht7B8Y4jTo7mTGL8BMVBKqd+69Uj5
            0yqc1MaJNSSxEzCi06rT7SpYlm67ATRGXVQ/13l69Un1aOrr6Vf2T+yFRnSQK5dV
            h1aYaUbqOreiUcu+oRpoe9Q/XQvYnNLKumHVIYN0mQ7ouSIZ7SXcoBHGipdXwBO9
            g3st1zTjdR9k/LSyPc1rxX6lZ/Vxbhc2ckR1HiMDsiqVPncnVpVs3MAT/9LDJJB1
            RCKlclKdTJLx67GfHa1NA28v3zHKkQG9+BrqlIrtzyF6qPzNegdxqidT4agjv0HJ
            U3ei/6YbImUTgVPOhtLIfdB6SzLSf18ocmQUMc6aGKUCqu/Zr8Ww0TzUbDV+OOae
            HulFrdGZKTKlseXFYpyfSPdmGFPaAHh8nXj7klVTvwelDdW52TWFNCDk0aca5i/5
            DKGTzdbC9L7SY0Far5o1CUvCoi4qZjx2RQAc0ZC3vBfHX+rfjofOXCS3Y7ZYTtMu
            cbAmgULqPtaJgVe/kjvr8BktG/XuMKfTUWNKYLUE3eOKLhFPeum/F21KGLoolae7
            S0dESpuo27TBJM1Bu7MvS8sd5IxKu1EGB6ABtaAAu6Q2GLbBnkNRe0W0JAWSi2fH
            E4gYWLrTpCURwnFv+c0zIDS2crUv8WYQgFzb51RKioS2bhx0WnPBtrzaW3e5UfNs
            D3pTct6eXR+bvN6IQ8aQkALdpIdeZ1ca8L7FgYVsMsCcJA5mTnYeV80NjcinHLkY
            pXYtERKFzYtWE929DKCKwDQrK97jj5b6dUuysIcXnBE8k5hqgQNW65RUC5PLnexK
            qSkP8S7Bqi5lbJvj1ZB1PDZsYBQGwGG8IgM6H9H04REdA5uIE7mDy1BsPqf/MFeY
            PovwFoL7sA9DAFMTyCwTkpGKYWWhMzj/4RqZLB+z0QMqpnmkGMi6T4oLwZnhDPa9
            d6FP3WoGCTUUNI46iXRDSuijZ2Npxr4s+Q5nKzQ/zgSsayLgz0dWi8RdcKaOaMZJ
            pIMK4hhZDBpDfnojpU7+RPZwhutpe5+leDXwuPcPCpKSJu+zNsDiGDOgKCGM1jcy
            yAqkd+YtFB26gYVPcNpo2v9KhMtt53klToqX5zVlN0r0CSrwXL1mVK/D/XLwriMm
            lctmaOr+zEBpvZC7UouD76L7zb2TsomSliHtdNgIc4/BA+6xBVEIUfyTGfFx6gzt
            C5e1ufte+YUYa8UgmPnrR29nt8x2ZdR1h5dctFpQ/GQQBxm/djRfD98eCe/p+4AN
            wRTka+CHmhlcwGhw4j0mMdrnHDmUSByHYcQNB8W/ypXnGLeyJYWvA+00F1pG1Xrz
            UY4yp/wapEgnMqgah/ck+NLngLOjnUUaOA91wtaAzHIT6rHUpZ05SuOBChyQgY1S
            +T+yA+LYsbX6j2Cy1YXZE11kiEbxOLhpUyQtK7Hy7N84m03nZRgXuOTmSzM/GqxS
            OpPydIqcOP+8Kc7UV7b5eBsIpnoZddAxzNcVRcADdDQFbCQ00T5sS+6/RvwSIiwL
            LszWFZ1a6o5VTXoJZSsGv3ymmacZnnFtBd1VMEGo8rMD0japurqvufpSjyiiyiqn
            gLlAODwJmqZaAHS4P9HwvFt7XkbCXlSDizy8/JX4fx1HGzuolENPpYlS/ct38WE3
            JpMwbbpOjyFtHI5cr/D+g2ClHGB2NkQWn9xqgmfy4/kJphsqZ4vOaukEA6g2sae3
            6M2LVMNwh6nhREbZXmkI0u7b/MZT4C/fdx9wGnm55aJu0KlHhCBw87VwF0IhEhnn
            YXYsN/DQodG5dQ/uV34SCBFcZqwH7Akeaj/EqmolO8uoaO3TFU3K9RYvYV6FSQps
            o0LzTEOsYaPqa/7v2FDhkOsdjaTSi17O6xZ4wCQz7NXUiyU2QEJX6Mp771hV8rgT
            7S9MQJRFozF8m+GjWuL7TSuHkhuQS/LBTbUUzuBFJRz8J2N02xXJneoVrN4ZfG61
            JJiOObYyh764Z2hlqqO60bQ7jKsVy/J6SYdZ4yA6vzaelyQvCwFUFJ8UrCM823Oi
            K3+48JMlvyrOg7trXbihIaK2ghSaaRMczOUiKYQLET/HsLzFhAW/6H8flf/C6W/F
            WWVn6UNk36ptnVpuuZrk3fQk
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9881_ML_DSA_87_PUBLIC_KEY = """
            -----BEGIN PUBLIC KEY-----
            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
            5VvgYiIvi6kKl0BzMmsxISrs4KNKYA==
            -----END PUBLIC KEY-----
            """;

    private static final String RFC9935_ML_KEM_512_PRIVATE_KEY_SEED = """
            -----BEGIN PRIVATE KEY-----
            MFQCAQAwCwYJYIZIAWUDBAQBBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9935_ML_KEM_512_PRIVATE_KEY_EXPANDED = """
            -----BEGIN PRIVATE KEY-----
            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
            JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9935_ML_KEM_512_PRIVATE_KEY_BOTH ="""
            -----BEGIN PRIVATE KEY-----
            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
            Pj8=
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9935_ML_KEM_512_PUBLIC_KEY = """
            -----BEGIN PUBLIC KEY-----
            MIIDMjALBglghkgBZQMEBAEDggMhADmVgV5ZfRBDVc8pqlMzyTJRhp1bzb5IcST2
            Ari2pmwWxHYWSK12XPXYAGtRXpBafwrAdrDGLvoygVPnylcBaZ8TBfHmvG+QsOSb
            aTUSts6ZKouAFt38GmYsfj+WGcvYad13GvMIlszVkYrGy3dGbF53mZbWf/mqvJdQ
            Pyx7fi0ADYZFD7GAfKTKvaRlgloxx4mht6SRqzhydl0yDQtxkg+iE8lAk0Frg7gS
            Tmn2XmLLUADcw3qpoP/3OXDEdy81fSQYnKb1MFVowOI3ajdipoxgXlY8XSCVcuD8
            dTLKKUcpU1VntfxBPF6HktJGRTbMgI+YrddGZPFBVm+QFqkKVBgpqYoEZM5BqLtE
            wtT6PCwglGByjvFKGnxMm5jRIgO0zDUpFgqasteDj3/2tTrgWqMafWRrevpsRZMl
            JqPDdVYZvplMIRwqMcBbNEeDbLIVC+GCna5rBMVTXP9Ubjkrp5dBFyD5JPSQpaxU
            lfITVtVQt4KmTBaItrZVvMeEIZekNML2Vjtbfwmni8xIgjJ4NWHRb0y6tnVUAAUH
            gVcMZmBLgXrRJSKUc26LAYYaS1p0UZuLb+UUiaUHI5Llh2JscTd2V10zgGocjicy
            r5fCaA9RZmMxxOuLvAQxxPloMtrxs8RVKPuhU/bHixwZhwKUfM0zdyekb7U7oR3l
            y0GRNGhZUWy2rXJADzzyCbI2rvNaWArIfrPjD6/WaXPKin3SZ1r0H3oXthQzzRr4
            D3cIhp9mVIhJeYCxrBCgzctjagDthoGzXkKRJMqANQcluF+DperDpKPMFgCQPmUp
            NWC5szblrw1SnawaBIEZMCy3qbzBELlIUb8CEX8ZncSFqFK3Rz8JuDGmgx1bVMC3
            kNIlz2u5LZRiomzbM92lEjx6rw4moLg2Ve6ii/OoB0clAY/WuuS2Ac9huqtxp6PT
            UZejQ+dLSicsEl1UCJZCbYW3lY07OKa6mH7DciXHtEzbEt3kU5tKsII2NoPwS/eg
            nMXEHf6DChsWLgsyQzQ2LwhKFEZ3IzRLrdAA+NjFN8SPmY8FMHzr0e3guBw7xZoG
            WhttY7Js
            -----END PUBLIC KEY-----
            """;
    
    private static final String RFC9935_ML_KEM_768_PRIVATE_KEY_SEED = """
            -----BEGIN PRIVATE KEY-----
            MFQCAQAwCwYJYIZIAWUDBAQCBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9935_ML_KEM_768_PRIVATE_KEY_EXPANDED = """
            -----BEGIN PRIVATE KEY-----
            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
            JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9935_ML_KEM_768_PRIVATE_KEY_BOTH ="""
            -----BEGIN PRIVATE KEY-----
            MIIJvgIBADALBglghkgBZQMEBAIEggmqMIIJpgRAAAECAwQFBgcICQoLDA0ODxAR
            EhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+PwSC
            CWAn0qd/M3VvYSCO8ROr6CWVhz1KvHMOW11nlSm/akzrY4NCcjGoYS9BVQUVrLpS
            5I6ti5QoM7vmhl0T0Up50sXD4H8KBW2N56rfyroFjEk8gLN8q4xWJ1O7O6a27IKX
            +IXqp1QNUwAVqEQG5VsTZrV34jbOWKJtih61pE1UIyPCFn2b9KR/mFaZygW65DuN
            7GF/AjgKOJCv1LjH7H7eJlU6Al885bxdemITAwQjXLGtSDa1ZrW4Y72b20WihEpw
            R7bI04PkSFJeBAtNyKK0jGw3yW1i1D8/2I4ogcQKIFyeJI9lK1kngad5+GiA8qFH
            tnhj85HMGlqQjACV4HISKR4u+KNuuanAxgcyJbNHA6SvBJOCxHVz2mj96SRa1ETj
            Gx+9tSHx9h83vAzvKSBn5nDSih/9kE9vEZCplpGKEwN6bKvzw3O/gpbNN6szundG
            gJzD+K3hs2Ob1Xv8xpZQqq8d4Zj8TARjKZ5SxGF4DMQo/F0EpcUYUMumwqUnQ0Bn
            V5PdoJvkTCnmOVxl+F0qCnxt9BHmkRsfLLbDUc0uh19Rtji+d2CX6T4vKy+D2gvu
            9KqFup52OrZFAqDKUiLp6rWztwiO1SBg6Mgmm5Q6casK4cWxtofS4BnPgDa8+b9u
            e6w6qjbkFmD6pFQPJkjNk6GJ7Fwt6nC6yqpP/JBvkIEOobZ78k8seM9rqIGq6mHA
            ZSv/lbG65EJtF3O5zCyoLCHjjGNuOxxSMkSYawvoqD9d1c8tVHYvs8Xr9ZuOiFMC
            sc5HAz7fdg9OApvkC21WaxnddYrNXHQSh4ExJE+QFyxT8mZjwh2QUwHUi6+RyRfM
            d3np2IAswQ2Jo3BQmaKtOjqIlnQ8EURpgJO+JX2stm3HhSKLkSyNll0Uqig0LDrE
            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
            Pj8=
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9935_ML_KEM_768_PUBLIC_KEY = """
            -----BEGIN PUBLIC KEY-----
            MIIEsjALBglghkgBZQMEBAIDggShACmKoQ1CPI3aBp0CvFnmzfA6CWuLPaTKubgM
            pKFJB2cszvHsT68jSgvFt+nUc/KzEzs7JqHRdctnp4BZGWmcAvdlMbmcX4kYBwS7
            TKRTXFuJcmecZgoHxeUUuHAJyGLrj1FXaV77P8QKne9rgcHMAqJJrk8JStDZvTSF
            wcHGgIBSCnyMYyAyzuc4FU5cUXbAfaVgJHdqQw/nbqz2ZaP3uDIQIhW8gvEJOcg1
            VwQzao+sHYHkuwSFql18dNa1m75cXpcqDYusQRtVtdVVfNaAoaj3G064a8SMmgUJ
            cxpUvZ1ykLJ5Y+Q3Lcmxmc/crAsBrNKKYjlREuTENkjWIsSMgjTQFEDozDdskn8j
            pa/JrAR0xmInTkJFJchVLs47P+JlFt6QG8fVFb3olVjmJslcgLkzQvgBAATznmxs
            lIccXjRMqzlmyDX5qWpZr9McQChrOLHBp4RwurlHUYk0RTzoZzapGfH1ptUQqG9U
            VPw5gMtcdlvSvV97NrFBDWY1yM60fE3aDXaijqyTnHHDAkgEhmxxYmZYRCFjwsIh
            F+UKzvzmN4qYVlIwKk7wws4Mxxa3eW4ray43d9+hrD2iWaMbWptTD4y2OKgaYqww
            GEmrr5WnMBvaMAaJCb/bfmfbzLs4pVUaJbGjoPaFdIrVdT2IgPABbGJ0hhZjhMVX
            H+I2WQA2TQODEeLYdds2ZoaTK17GAkMKNp6Hpu9cM4eGZXglvUwFes65I+sJNeaQ
            XmO0ztf4CFenc91ksVDSZhLqmsEgUtsgF78YQ8y0sygbaQ3HKK36hcACgbjjwJKH
            M1+Fa0/CiS9povV5Ia2gGRTECYhmLVd2lmKnhjUbm2ZJPat5WU2YbeIQDWW6D/Tq
            WLgVONJKRDWiWPrCVASqf0H2WLE4UGXhWNy2ARVzJyD0BFmqrBXkBpU6kKxSmX0c
            zQcAYO/GXbnmUzVEZ/rVbscTyG51QMQjrPJmn1L6b0rGiI2HHvPoR8ApqKr7uS4X
            skqgebH0GbphdbRCr7EZCdSla3CgM1soc5IYqnyTSOLDwvPrPRWkHmQXwN2Uv+sh
            QZsxGnuxOhgLvoMyGKmmsXRHzIXyJYWVh6cwdwSay8/UTQ8CVDjhXRU4Jw1Ybhv4
            MZKpRZz2PA6XL4UpdnmDHs8SFQmFHLg0D28Qew+hoO/Rs2qBibwIXE9ct4TlU/Qb
            kY+AOXzhlW94W+43fKmqi+aZitowwmt8PYxrVSVMyWIDsgxCruCsTh67QI5JqeP4
            edCrB4XrcCVCXRMFoimcAV4SDRY7DhlJTOVyU9AkbRgnRcuBl6t0OLPBu3lyvsWj
            BuujVnhVwBRpn+9lrlTHcKDYXBhADPZCrtxmB3e6SxOFAr1aeBL2IfhKSClrmN1D
            IrbxWCi4qPDgCoukSlPDqLFDVxsHQKvVZ9rxzenHnCBLbV4lnRdmoxu7y05qBc9F
            AhdrMBwcL0Ekd1AVe87IXoCbMKTWDXdHzdD1uZqoyCaYdRd5OqqAgKCxJKhVjfcr
            vje3X07btr6CFtbGM/srIoDiURPYaV5DSBw+6zl+sZJQUim2eiAeqJPD4ssy2ovD
            QvpN6gV4
            -----END PUBLIC KEY-----
            """;

    private static final String RFC9935_ML_KEM_1024_PRIVATE_KEY_SEED = """
            -----BEGIN PRIVATE KEY-----
            MFQCAQAwCwYJYIZIAWUDBAQDBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9935_ML_KEM_1024_PRIVATE_KEY_EXPANDED = """
            -----BEGIN PRIVATE KEY-----
            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
            JCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9935_ML_KEM_1024_PRIVATE_KEY_BOTH ="""
            -----BEGIN PRIVATE KEY-----
            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
            Pj8=
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9935_ML_KEM_1024_PUBLIC_KEY = """
            -----BEGIN PUBLIC KEY-----
            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
            uYOILhF1
            -----END PUBLIC KEY-----
            """;

    @Test
    public void testPQCKeyGenKEM_PlusToInterop() throws Exception {
        String pqcAlgorithm = "ML-KEM-512";
        boolean same = false;

        //This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        keyPairGenPlus = KeyPairGenerator.getInstance(pqcAlgorithm, getProviderName());
        keyFactoryPlus = KeyFactory.getInstance(pqcAlgorithm, getProviderName());
        keyPairGenInterop = KeyPairGenerator.getInstance(pqcAlgorithm, getInteropProviderName());
        keyFactoryInterop = KeyFactory.getInstance(pqcAlgorithm, getInteropProviderName());

        KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);
        PublicKey publicKeyPlus = keyPairPlus.getPublic();
        PrivateKey privateKeyPlus = keyPairPlus.getPrivate();
        byte[] publicKeyBytesPlus = publicKeyPlus.getEncoded();
        byte[] privateKeyBytesPlus = privateKeyPlus.getEncoded();

        PKCS8EncodedKeySpec privateKeySpecPlus = new PKCS8EncodedKeySpec(privateKeyBytesPlus);
        EncodedKeySpec publicKeySpecPlus = new X509EncodedKeySpec(publicKeyBytesPlus);
        PublicKey publicKeyInterop = keyFactoryInterop.generatePublic(publicKeySpecPlus);
        PrivateKey privateKeyInterop = keyFactoryInterop.generatePrivate(privateKeySpecPlus);

        // BC private keys do not currently conform to the Draft standard for these keys
        // So we know the keys will not compare
        if (getInteropProviderName().equals(Utils.PROVIDER_SunJCE)) {
            same = Arrays.equals(privateKeyBytesPlus, privateKeyInterop.getEncoded());
            assertTrue(same);
        }

        // The original and new keys are the same
        same = Arrays.equals(publicKeyBytesPlus, publicKeyInterop.getEncoded());
        assertTrue(same);
    } 

    @Test
    public void testPQCKeyGenKEMAutoKeyConvertion() throws Exception {
        String pqcAlgorithm = "ML-KEM-512";

        //This is not in the FIPS provider yet and BouncyCastle  does not support this test.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        KEM kemInterop = KEM.getInstance(pqcAlgorithm, getProviderName());

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(pqcAlgorithm, getInteropProviderName());
        KeyPair keyPair = generateKeyPair(keyPairGen);

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
            
        KEM.Encapsulator encr = kemInterop.newEncapsulator(publicKey);
        KEM.Encapsulated enc = encr.encapsulate(0, 32, "AES");
        if (enc == null) {
            System.out.println("enc = null");
            fail("KEMPlusCreatesInteropGet failed no enc.");
        }
        SecretKey keyE = enc.key();

        KEM.Decapsulator decr = kemInterop.newDecapsulator(privateKey);
        SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 32, "AES");

        assertArrayEquals(keyE.getEncoded(), keyD.getEncoded(), "Secrets do NOT match");
    } 

    @Test
    public void testPQCKeyGenKEM_Interop() throws Exception {
        String pqcAlgorithm = "ML-KEM-512";
        boolean same = false;

        //This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        keyPairGenPlus = KeyPairGenerator.getInstance(pqcAlgorithm, getProviderName());
        keyFactoryPlus = KeyFactory.getInstance(pqcAlgorithm, getProviderName());
        keyPairGenInterop = KeyPairGenerator.getInstance(pqcAlgorithm, getInteropProviderName());
        keyFactoryInterop = KeyFactory.getInstance(pqcAlgorithm, getInteropProviderName());

        KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);
        PublicKey publicKeyInterop = keyPairInterop.getPublic();
        PrivateKey privateKeyInterop = keyPairInterop.getPrivate();
        byte[] publicKeyBytesInterop = publicKeyInterop.getEncoded();
        byte[] privateKeyBytesInterop = privateKeyInterop.getEncoded();

        PKCS8EncodedKeySpec privateKeySpecInterop = new PKCS8EncodedKeySpec(privateKeyBytesInterop);
        EncodedKeySpec publicKeySpecInterop = new X509EncodedKeySpec(publicKeyBytesInterop);
        PublicKey publicKeyPlus = keyFactoryPlus.generatePublic(publicKeySpecInterop);
        PrivateKey privateKeyPlus = keyFactoryPlus.generatePrivate(privateKeySpecInterop);

        // BC private keys do not currently conform to the Draft standard for these keys
        // So we know the keys will not compare
        if (getInteropProviderName().equals(Utils.PROVIDER_SunJCE)) {
            same = Arrays.equals(privateKeyBytesInterop, privateKeyPlus.getEncoded());
            assertTrue(same);
        }

        same = Arrays.equals(publicKeyBytesInterop, publicKeyPlus.getEncoded());
        assertTrue(same);

    }

    @Test
    public void testPQCKeyGenKEM_PlusToInteropRAW() throws Exception {
        String pqcAlgorithm = "ML-KEM-512";
        boolean same = false;

        //This is not in the FIPS provider yet and Bouncy Castle does not support this test.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        keyPairGenPlus = KeyPairGenerator.getInstance(pqcAlgorithm, getProviderName());
        keyFactoryPlus = KeyFactory.getInstance(pqcAlgorithm, getProviderName());
        keyPairGenInterop = KeyPairGenerator.getInstance(pqcAlgorithm, getInteropProviderName());
        keyFactoryInterop = KeyFactory.getInstance(pqcAlgorithm, getInteropProviderName());

        KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);
        PublicKey publicKeyInterop = keyPairInterop.getPublic();
        PrivateKey privateKeyInterop = keyPairInterop.getPrivate();
        byte[] publicKeyBytesInterop = publicKeyInterop.getEncoded();
        byte[] privateKeyBytesInterop = privateKeyInterop.getEncoded();

        EncodedKeySpec eksInterop = keyFactoryInterop.getKeySpec(publicKeyInterop, EncodedKeySpec.class);
        PublicKey pub = keyFactoryPlus.generatePublic(eksInterop); 
        EncodedKeySpec eksPrivInterop = keyFactoryInterop.getKeySpec(privateKeyInterop, EncodedKeySpec.class);
        PrivateKey priv = keyFactoryPlus.generatePrivate(eksPrivInterop);
        same = Arrays.equals(privateKeyBytesInterop, priv.getEncoded());
        assertTrue(same);
        
        // The original and new keys are the same
        same = Arrays.equals(publicKeyBytesInterop, pub.getEncoded());
        assertTrue(same);
    }

    @Test
    public void testPQCKeyGenMLDSA_PlusToInterop() throws Exception {
        String pqcAlgorithm = "ML-DSA-65";
        boolean same = false;

        //This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        keyPairGenPlus = KeyPairGenerator.getInstance(pqcAlgorithm, getProviderName());
        keyFactoryPlus = KeyFactory.getInstance(pqcAlgorithm, getProviderName());
        keyPairGenInterop = KeyPairGenerator.getInstance(pqcAlgorithm, getInteropProviderName2());
        keyFactoryInterop = KeyFactory.getInstance(pqcAlgorithm, getInteropProviderName2());

        KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);
        PublicKey publicKeyPlus = keyPairPlus.getPublic();
        PrivateKey privateKeyPlus = keyPairPlus.getPrivate();
        byte[] publicKeyBytesPlus = publicKeyPlus.getEncoded();
        byte[] privateKeyBytesPlus = privateKeyPlus.getEncoded();

        PKCS8EncodedKeySpec privateKeySpecPlus = new PKCS8EncodedKeySpec(privateKeyBytesPlus);
        EncodedKeySpec publicKeySpecPlus = new X509EncodedKeySpec(publicKeyBytesPlus);
        PublicKey publicKeyInterop = keyFactoryInterop.generatePublic(publicKeySpecPlus);
        //BC is using a different encoding today for thier ML-DSA private keys.
        // So we can not compare these today.
        if (getInteropProviderName().equals(Utils.PROVIDER_SunJCE)) {
            PrivateKey privateKeyInterop = keyFactoryInterop.generatePrivate(privateKeySpecPlus);
            same = Arrays.equals(privateKeyBytesPlus, privateKeyInterop.getEncoded());
            assertTrue(same);
        }
        
        // The original and new keys are the same
        same = Arrays.equals(publicKeyBytesPlus, publicKeyInterop.getEncoded());
        assertTrue(same);
    } 

    @Test
    public void testPQCKeyGenMLDSA_Interop() throws Exception {        
        String pqcAlgorithm = "ML-DSA-65";
        boolean same = false;

        //This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        keyPairGenPlus = KeyPairGenerator.getInstance(pqcAlgorithm, getProviderName());
        keyFactoryPlus = KeyFactory.getInstance(pqcAlgorithm, getProviderName());
        keyPairGenInterop = KeyPairGenerator.getInstance(pqcAlgorithm, getInteropProviderName2());
        keyFactoryInterop = KeyFactory.getInstance(pqcAlgorithm, getInteropProviderName2());

        KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);
        PublicKey publicKeyInterop = keyPairInterop.getPublic();
        PrivateKey privateKeyInterop = keyPairInterop.getPrivate();
        byte[] publicKeyBytesInterop = publicKeyInterop.getEncoded();
        byte[] privateKeyBytesInterop = privateKeyInterop.getEncoded();

        PKCS8EncodedKeySpec privateKeySpecInterop = new PKCS8EncodedKeySpec(privateKeyBytesInterop);
        EncodedKeySpec publicKeySpecInterop = new X509EncodedKeySpec(publicKeyBytesInterop);
        PublicKey publicKeyPlus = keyFactoryPlus.generatePublic(publicKeySpecInterop);
        PrivateKey privateKeyPlus = keyFactoryPlus.generatePrivate(privateKeySpecInterop);

        //BC is using a different encoding today for thier ML-DSA private keys.
        // So we can not compare these today.
        if (getInteropProviderName().equals(Utils.PROVIDER_SunJCE)) {
            same = Arrays.equals(privateKeyBytesInterop, privateKeyPlus.getEncoded());
            assertTrue(same);
        }  

        same = Arrays.equals(publicKeyBytesInterop, publicKeyPlus.getEncoded());
        assertTrue(same);
    }

    @Test
    public void testPQCKeyGenMLDSA_PlusToInteropRAW() throws Exception {
        String pqcAlgorithm = "ML-DSA-65";
        boolean same = false;

        //This is not in the FIPS provider yet and Bouncy Castle does not support this test.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        keyPairGenPlus = KeyPairGenerator.getInstance(pqcAlgorithm, getProviderName());
        keyFactoryPlus = KeyFactory.getInstance(pqcAlgorithm, getProviderName());
        keyPairGenInterop = KeyPairGenerator.getInstance(pqcAlgorithm, getInteropProviderName2());
        keyFactoryInterop = KeyFactory.getInstance(pqcAlgorithm, getInteropProviderName2());

        KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);
        PublicKey publicKeyInterop = keyPairInterop.getPublic();
        PrivateKey privateKeyInterop = keyPairInterop.getPrivate();
        byte[] publicKeyBytesInterop = publicKeyInterop.getEncoded();
        byte[] privateKeyBytesInterop = privateKeyInterop.getEncoded();

        EncodedKeySpec eksInterop = keyFactoryInterop.getKeySpec(publicKeyInterop, EncodedKeySpec.class);
        PublicKey pub = keyFactoryPlus.generatePublic(eksInterop); 
        EncodedKeySpec eksPrivInterop = keyFactoryInterop.getKeySpec(privateKeyInterop, EncodedKeySpec.class);
        PrivateKey priv = keyFactoryPlus.generatePrivate(eksPrivInterop);
        
        //BC is using a different encoding today for thier ML-DSA private keys.
        // So we can not compare these today.
        if (getInteropProviderName().equals(Utils.PROVIDER_SunJCE)) {
            same = Arrays.equals(privateKeyBytesInterop, priv.getEncoded());
            assertTrue(same);
        }
        
        // The original and new keys are the same
        same = Arrays.equals(publicKeyBytesInterop, pub.getEncoded());
        assertTrue(same);
    }

    protected KeyPair generateKeyPair(KeyPairGenerator keyPairGen) throws Exception {
        KeyPair keyPair = keyPairGen.generateKeyPair();

        if (keyPair.getPrivate() == null) {
            fail("Private key is null");
        }

        if (keyPair.getPublic() == null) {
            fail("Public key is null");
        }

        return keyPair;
    }
 
    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testSignInteropAndVerifyPlus(String algorithm) throws Exception {
        //This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(algorithm.equalsIgnoreCase("ML-DSA") && getInteropProviderName2().equalsIgnoreCase("BC"));

        try {
            keyPairGenInterop = KeyPairGenerator.getInstance(algorithm, getInteropProviderName2());
            KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);

            PublicKey publicKeyInterop = keyPairInterop.getPublic();
            PrivateKey privateKeyInterop = keyPairInterop.getPrivate();

            Signature signingInterop = Signature.getInstance(algorithm, getInteropProviderName2());
            signingInterop.initSign(privateKeyInterop);
            signingInterop.update(origMsg);
            byte[] signedBytesInterop = signingInterop.sign();

            X509EncodedKeySpec x509SpecInterop = new X509EncodedKeySpec(
                publicKeyInterop.getEncoded());

            KeyFactory keyFactoryPlus = KeyFactory.getInstance(algorithm, getProviderName());
            PublicKey pubPlus = keyFactoryPlus.generatePublic(x509SpecInterop);

            Signature verifyingPlus = Signature.getInstance(algorithm, getProviderName());
            verifyingPlus.initVerify(pubPlus);
            verifyingPlus.update(origMsg);
            assertTrue(verifyingPlus.verify(signedBytesInterop), "Signature verification failed");
        } catch (Exception ex) {
            ex.printStackTrace();
            throw ex;
        }
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testSignInteropKeysPlusSignVerify(String algorithm) {
        //This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName2()));

        try {
            keyPairGenInterop = KeyPairGenerator.getInstance(algorithm, getInteropProviderName2());
            KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);

            PublicKey publicKeyInterop = keyPairInterop.getPublic();
            PrivateKey privateKeyInterop = keyPairInterop.getPrivate();
            PKCS8EncodedKeySpec privateKeySpecInterop = new PKCS8EncodedKeySpec(privateKeyInterop.getEncoded());
            EncodedKeySpec publicKeySpecInterop = new X509EncodedKeySpec(publicKeyInterop.getEncoded());
            KeyFactory keyFactoryPlus = KeyFactory.getInstance(algorithm, getProviderName());
            PrivateKey privPlus = keyFactoryPlus.generatePrivate(privateKeySpecInterop);
            PublicKey pubPlus = keyFactoryPlus.generatePublic(publicKeySpecInterop);

            Signature signingInterop = Signature.getInstance(algorithm, getProviderName());
            signingInterop.initSign(privPlus);
            signingInterop.update(origMsg);
            byte[] signedBytesInterop = signingInterop.sign();

            Signature verifyingPlus = Signature.getInstance(algorithm, getProviderName());
            verifyingPlus.initVerify(pubPlus);
            verifyingPlus.update(origMsg);
            assertTrue(verifyingPlus.verify(signedBytesInterop), "Signature verification failed");
        } catch (Exception ex) {
            ex.printStackTrace();
            fail("SignInteropAndVerifyPlus failed");
        }
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testSignPlusKeysInteropSignVerify(String algorithm) {
        //This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName2()));

        try {
            keyPairGenPlus = KeyPairGenerator.getInstance(algorithm, getProviderName());
            KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);

            PublicKey publicKeyPlus = keyPairPlus.getPublic();
            PrivateKey privateKeyPlus = keyPairPlus.getPrivate();
            PKCS8EncodedKeySpec privateKeySpecPlus = new PKCS8EncodedKeySpec(privateKeyPlus.getEncoded());
            EncodedKeySpec publicKeySpecPlus = new X509EncodedKeySpec(publicKeyPlus.getEncoded());
            KeyFactory keyFactoryInterop = KeyFactory.getInstance(algorithm, getInteropProviderName2());
            PrivateKey privInterop = keyFactoryInterop.generatePrivate(privateKeySpecPlus);
            PublicKey pubInterop = keyFactoryInterop.generatePublic(publicKeySpecPlus);

            Signature signingInterop = Signature.getInstance(algorithm, getInteropProviderName2());
            signingInterop.initSign(privInterop);
            signingInterop.update(origMsg);
            byte[] signedBytesInterop = signingInterop.sign();

            Signature verifyingPlus = Signature.getInstance(algorithm, getInteropProviderName2());
            verifyingPlus.initVerify(pubInterop);
            verifyingPlus.update(origMsg);
            assertTrue(verifyingPlus.verify(signedBytesInterop), "Signature verification failed");
        } catch (Exception ex) {
            ex.printStackTrace();
            fail("SignInteropAndVerifyPlus failed");
        }
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testSignPlusAndVerifyInterop(String algorithm) {
        try {
            //This is not in the FIPS provider yet.
            assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

            keyPairGenPlus = KeyPairGenerator.getInstance(algorithm, getProviderName());
            KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);

            PublicKey publicKeyPlus = keyPairPlus.getPublic();
            PrivateKey privateKeyPlus = keyPairPlus.getPrivate();

            Signature signingPlus = Signature.getInstance(algorithm, getProviderName());
            signingPlus.initSign(privateKeyPlus);
            signingPlus.update(origMsg);
            byte[] signedBytesPlus = signingPlus.sign();

            X509EncodedKeySpec x509SpecInterop = new X509EncodedKeySpec(
                publicKeyPlus.getEncoded());

            KeyFactory keyFactoryInterop = KeyFactory.getInstance(algorithm, getInteropProviderName2());
            PublicKey pubInterop = keyFactoryInterop.generatePublic(x509SpecInterop);

            Signature verifyingPlus = Signature.getInstance(algorithm, getInteropProviderName2());
            verifyingPlus.initVerify(pubInterop);
            verifyingPlus.update(origMsg);
            assertTrue(verifyingPlus.verify(signedBytesPlus), "Signature verification failed");
        } catch (Exception ex) {
            ex.printStackTrace();
            fail("SignPlusAndVerifyInterop failed");
        }
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testKEMPlusKeyInteropAll(String Algorithm) {
        //This is not in the FIPS provider yet and Oracle Private keys have an extra Octet in them.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        try {
            KEM kemInterop = KEM.getInstance("ML-KEM", getInteropProviderName());

            keyPairGenPlus = KeyPairGenerator.getInstance(Algorithm, getProviderName());
            KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);

            PublicKey publicKeyPlus = keyPairPlus.getPublic();
            PrivateKey privateKeyPlus = keyPairPlus.getPrivate();
            
            PKCS8EncodedKeySpec privateKeySpecPlus = new PKCS8EncodedKeySpec(privateKeyPlus.getEncoded());
            EncodedKeySpec publicKeySpecPlus = new X509EncodedKeySpec(publicKeyPlus.getEncoded());
            KeyFactory keyFactoryPlus = KeyFactory.getInstance(Algorithm, getInteropProviderName());
            PrivateKey privateKeyInterop = keyFactoryPlus.generatePrivate(privateKeySpecPlus);
            PublicKey publicKeyInterop = keyFactoryPlus.generatePublic(publicKeySpecPlus);

            KEM.Encapsulator encr = kemInterop.newEncapsulator(publicKeyInterop);
            KEM.Encapsulated enc = encr.encapsulate(0, 32, "AES");
            if (enc == null) {
                System.out.println("enc = null");
                fail("KEMPlusCreatesInteropGet failed no enc.");
            }
            SecretKey keyE = enc.key();

            KEM.Decapsulator decr = kemInterop.newDecapsulator(privateKeyInterop);
            SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 32, "AES");

            assertArrayEquals(keyE.getEncoded(), keyD.getEncoded(), "Secrets do NOT match");
        } catch (Exception ex) {
            ex.printStackTrace();
            fail("KEMPlusCreatesInteropGet failed");
        }
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testKEMInteropKeyPlusAll(String Algorithm) {
        //This is not in the FIPS provider yet and Oracle Private keys have an extra Octet in them.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        try {
            KEM kemPlus = KEM.getInstance(Algorithm, getProviderName());

            keyPairGenInterop = KeyPairGenerator.getInstance(Algorithm, getInteropProviderName());
            KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);

            PublicKey publicKeyInterop = keyPairInterop.getPublic();
            PrivateKey privateKeyInterop = keyPairInterop.getPrivate();
            
            PKCS8EncodedKeySpec privateKeySpecInterop = new PKCS8EncodedKeySpec(privateKeyInterop.getEncoded());
            EncodedKeySpec publicKeySpecInterop = new X509EncodedKeySpec(publicKeyInterop.getEncoded());
            KeyFactory keyFactoryPlus = KeyFactory.getInstance(Algorithm, getProviderName());
            PrivateKey privateKeyPlus = keyFactoryPlus.generatePrivate(privateKeySpecInterop);
            PublicKey publicKeyPlus = keyFactoryPlus.generatePublic(publicKeySpecInterop);

            KEM.Encapsulator encr = kemPlus.newEncapsulator(publicKeyPlus);
            KEM.Encapsulated enc = encr.encapsulate(0, 32, "AES");
            if (enc == null) {
                System.out.println("enc = null");
                fail("KEMPlusCreatesInteropGet failed no enc.");
            }
            SecretKey keyE = enc.key();

            KEM.Decapsulator decr = kemPlus.newDecapsulator(privateKeyPlus);
            SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 32, "AES");

            assertArrayEquals(keyE.getEncoded(), keyD.getEncoded(), "Secrets do NOT match");
        } catch (Exception ex) {
            ex.printStackTrace();
            fail("KEMPlusCreatesInteropGet failed");
        }
    }
        
    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testKEMPlusCreatesInteropGet(String Algorithm) {
        try {
            //This is not in the FIPS provider yet and Oracle Private keys have an extra Octet in them.
            assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

            KEM kemPlus = KEM.getInstance(Algorithm, getProviderName());
            KEM kemInterop = KEM.getInstance("ML-KEM", getInteropProviderName());

            keyPairGenPlus = KeyPairGenerator.getInstance(Algorithm, getProviderName());
            KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);

            PublicKey publicKeyPlus = keyPairPlus.getPublic();
            PrivateKey privateKeyPlus = keyPairPlus.getPrivate();
            
            X509EncodedKeySpec publicKeySpecInterop = new X509EncodedKeySpec(publicKeyPlus.getEncoded());
            KeyFactory keyFactoryInterop = KeyFactory.getInstance(Algorithm, getInteropProviderName());
            PublicKey publicKeyInterop = keyFactoryInterop.generatePublic(publicKeySpecInterop);

            KEM.Encapsulator encr = kemInterop.newEncapsulator(publicKeyInterop);
            KEM.Encapsulated enc = encr.encapsulate(0, 32, "AES");
            if (enc == null) {
                System.out.println("enc = null");
                fail("KEMPlusCreatesInteropGet failed no enc.");
            }
            SecretKey keyE = enc.key();

            KEM.Decapsulator decr = kemPlus.newDecapsulator(privateKeyPlus);
            SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 32, "AES");

            assertArrayEquals(keyE.getEncoded(), keyD.getEncoded(), "Secrets do NOT match");
        } catch (Exception ex) {
            ex.printStackTrace();
            fail("KEMPlusCreatesInteropGet failed");
        }
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testKEMInteropCreatesPlusGet(String Algorithm) {
        try {
            //This is not in the FIPS provider yet and Oracle Private keys have an extra Octet in them.
            assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

            KEM kemPlus = KEM.getInstance(Algorithm, getProviderName());
            KEM kemInterop = KEM.getInstance("ML-KEM", getInteropProviderName());

            keyPairGenInterop = KeyPairGenerator.getInstance(Algorithm, getInteropProviderName());
            KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);
            PublicKey publicKeyInterop = keyPairInterop.getPublic();
            PrivateKey privateKeyInterop = keyPairInterop.getPrivate();

            X509EncodedKeySpec publicKeySpecInterop = new X509EncodedKeySpec(publicKeyInterop.getEncoded());

            KeyFactory keyFactoryPlus = KeyFactory.getInstance(Algorithm, getProviderName());
            PublicKey publicKeyPlus = keyFactoryPlus.generatePublic(publicKeySpecInterop);
            KEM.Encapsulator encr = kemPlus.newEncapsulator(publicKeyPlus);
            KEM.Encapsulated enc = encr.encapsulate(0, 32, "AES");

            SecretKey keyE = enc.key();

            KEM.Decapsulator decr = kemInterop.newDecapsulator(privateKeyInterop);

            SecretKey keyD = decr.decapsulate(enc.encapsulation(), 0, 32, "AES");

            assertArrayEquals(keyE.getEncoded(), keyD.getEncoded(), "Secrets do NOT match");
        } catch (Exception ex) {
            ex.printStackTrace();
            fail("KEMInteropCreatesPlusGet failed");
        }
    }

    /**
     * Test ML-KEM interoperability using NamedParameterSpec to initialize KeyPairGenerator.
     * Tests encapsulation / decapsulation with different providers.
     *
     * @param parameterSet The ML-KEM parameter set (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
     * @throws Exception if any cryptographic operation fails
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testMLKEMInteropWithNamedParameterSpec(String parameterSet) throws Exception {
        // Not in FIPS provider yet and BC doesn't support this test
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        // Generate key pair using NamedParameterSpec with provider
        KeyPairGenerator keyPairGenPlus = KeyPairGenerator.getInstance("ML-KEM", getProviderName());
        keyPairGenPlus.initialize(new NamedParameterSpec(parameterSet));
        KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);
        
        // Encapsulate using provider
        KEM kemPlus = KEM.getInstance("ML-KEM", getProviderName());
        KEM.Encapsulator encapsulator = kemPlus.newEncapsulator(keyPairPlus.getPublic());
        KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, 32, "AES");
        
        SecretKey encapKey = encapsulated.key();
        byte[] encapsulation = encapsulated.encapsulation();
        
        // Decapsulate using interop provider
        KEM kemInterop = KEM.getInstance("ML-KEM", getInteropProviderName());
        KEM.Decapsulator decapsulator = kemInterop.newDecapsulator(keyPairPlus.getPrivate());
        SecretKey decapKey = decapsulator.decapsulate(encapsulation, 0, 32, "AES");
        
        // Verify that both keys match
        assertArrayEquals(encapKey.getEncoded(), decapKey.getEncoded(),
                "Encapsulated and decapsulated keys do not match for " + parameterSet);
    }

    /**
     * Test ML-KEM interoperability with empty parameters using NamedParameterSpec.
     * Tests encapsulation and decapsulation without from/to specification.
     *
     * @param parameterSet The ML-KEM parameter set (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
     * @throws Exception if any cryptographic operation fails
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testMLKEMInteropEmptyParamsWithNamedParameterSpec(String parameterSet) throws Exception {
        // Not in FIPS provider yet and BC doesn't support this test
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        // Generate key pair using NamedParameterSpec with interop provider
        KeyPairGenerator keyPairGenInterop = KeyPairGenerator.getInstance("ML-KEM", getInteropProviderName());
        keyPairGenInterop.initialize(new NamedParameterSpec(parameterSet));
        KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);
        
        // Encapsulate using interop provider (no from/to parameters)
        KEM kemInterop = KEM.getInstance("ML-KEM", getInteropProviderName());
        KEM.Encapsulator encapsulator = kemInterop.newEncapsulator(keyPairInterop.getPublic());
        KEM.Encapsulated encapsulated = encapsulator.encapsulate();
        
        SecretKey encapKey = encapsulated.key();
        byte[] encapsulation = encapsulated.encapsulation();
        
        // Decapsulate using provider (no from/to parameters)
        KEM kemPlus = KEM.getInstance("ML-KEM", getProviderName());
        KEM.Decapsulator decapsulator = kemPlus.newDecapsulator(keyPairInterop.getPrivate());
        SecretKey decapKey = decapsulator.decapsulate(encapsulation);
        
        // Verify that both keys match
        assertArrayEquals(encapKey.getEncoded(), decapKey.getEncoded(),
                "Encapsulated and decapsulated keys do not match for " + parameterSet);
    }

    /**
     * Test ML-KEM interoperability with smaller secret size using NamedParameterSpec.
     * Tests with 16 bytes instead of the default 32 bytes.
     *
     * @param parameterSet The ML-KEM parameter set (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
     * @throws Exception if any cryptographic operation fails
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testMLKEMInteropSmallerSecretWithNamedParameterSpec(String parameterSet) throws Exception {
        // Not in FIPS provider yet and BC doesn't support this test
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        // Generate key pair using NamedParameterSpec with provider
        KeyPairGenerator keyPairGenPlus = KeyPairGenerator.getInstance("ML-KEM", getProviderName());
        keyPairGenPlus.initialize(new NamedParameterSpec(parameterSet));
        KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);
        
        // Encapsulate using provider with smaller secret (16 bytes)
        KEM kemPlus = KEM.getInstance("ML-KEM", getProviderName());
        KEM.Encapsulator encapsulator = kemPlus.newEncapsulator(keyPairPlus.getPublic());
        KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, 16, "AES");
        
        SecretKey encapKey = encapsulated.key();
        byte[] encapsulation = encapsulated.encapsulation();
        
        // Decapsulate using interop provider with same secret size
        KEM kemInterop = KEM.getInstance("ML-KEM", getInteropProviderName());
        KEM.Decapsulator decapsulator = kemInterop.newDecapsulator(keyPairPlus.getPrivate());
        SecretKey decapKey = decapsulator.decapsulate(encapsulation, 0, 16, "AES");
        
        // Verify that both keys match
        assertArrayEquals(encapKey.getEncoded(), decapKey.getEncoded(),
                "Encapsulated and decapsulated keys do not match for " + parameterSet);
    }

    /**
     * Test bidirectional ML-KEM interoperability using NamedParameterSpec.
     * Tests both directions to and from providers.
     *
     * @param parameterSet The ML-KEM parameter set (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
     * @throws Exception if any cryptographic operation fails
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testMLKEMBidirectionalInteropWithNamedParameterSpec(String parameterSet) throws Exception {
        // Not in FIPS provider yet and BC doesn't support this test
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        // Test 1: Generate with provider, encapsulate with interop provider, decapsulate with provider
        KeyPairGenerator keyPairGenPlus = KeyPairGenerator.getInstance("ML-KEM", getProviderName());
        keyPairGenPlus.initialize(new NamedParameterSpec(parameterSet));
        KeyPair keyPairPlus = generateKeyPair(keyPairGenPlus);
        
        KEM kemInterop = KEM.getInstance("ML-KEM", getInteropProviderName());
        KEM.Encapsulator encapsulatorInterop = kemInterop.newEncapsulator(keyPairPlus.getPublic());
        KEM.Encapsulated encapsulatedInterop = encapsulatorInterop.encapsulate(0, 32, "AES");
        
        KEM kemPlus = KEM.getInstance("ML-KEM", getProviderName());
        KEM.Decapsulator decapsulatorPlus = kemPlus.newDecapsulator(keyPairPlus.getPrivate());
        SecretKey decapKeyPlus = decapsulatorPlus.decapsulate(encapsulatedInterop.encapsulation(), 0, 32, "AES");
        
        assertArrayEquals(encapsulatedInterop.key().getEncoded(), decapKeyPlus.getEncoded(),
                "Keys do not match for test 1 with " + parameterSet);
        
        // Test 2: Generate with interop provider, encapsulate with provider, decapsulate with interop provider
        KeyPairGenerator keyPairGenInterop = KeyPairGenerator.getInstance("ML-KEM", getInteropProviderName());
        keyPairGenInterop.initialize(new NamedParameterSpec(parameterSet));
        KeyPair keyPairInterop = generateKeyPair(keyPairGenInterop);
        
        KEM.Encapsulator encapsulatorPlus = kemPlus.newEncapsulator(keyPairInterop.getPublic());
        KEM.Encapsulated encapsulatedPlus = encapsulatorPlus.encapsulate(0, 32, "AES");
        
        KEM.Decapsulator decapsulatorInterop = kemInterop.newDecapsulator(keyPairInterop.getPrivate());
        SecretKey decapKeyInterop = decapsulatorInterop.decapsulate(encapsulatedPlus.encapsulation(), 0, 32, "AES");
        
        assertArrayEquals(encapsulatedPlus.key().getEncoded(), decapKeyInterop.getEncoded(),
                "Keys do not match for test 2 with " + parameterSet);
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void testMLKEMGetKeySpecPrivateInteropToPlus(String algorithm)
            throws Exception {
        // This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        // This test is for SunJCE/OpenJCEPlus interop, not BC.
        // assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName()));

        KeyFactory openjceplusKeyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        KeyPairGenerator interopKpg = KeyPairGenerator.getInstance(algorithm, getInteropProviderName());
        KeyPair interopKeyPair = interopKpg.generateKeyPair();
        PrivateKey interopPrivateKey = interopKeyPair.getPrivate();
        KeySpec interopPrivKeySpec = new PKCS8EncodedKeySpec(interopPrivateKey.getEncoded());
        PrivateKey openjceplusPrivateKey = openjceplusKeyFactory.generatePrivate(interopPrivKeySpec);

        KEM interopKem = KEM.getInstance(algorithm, getInteropProviderName());
        KEM.Encapsulator encapsulator =
                interopKem.newEncapsulator(interopKeyPair.getPublic());

        KEM.Encapsulated encapsulated = encapsulator.encapsulate();

        KEM openjceplusKem = KEM.getInstance(algorithm, getProviderName());
        KEM.Decapsulator decapsulator =
                openjceplusKem.newDecapsulator(openjceplusPrivateKey);

        SecretKey openjceplusSecret =
                decapsulator.decapsulate(encapsulated.encapsulation());

        assertArrayEquals(encapsulated.key().getEncoded(),
            openjceplusSecret.getEncoded());

        KeySpec keySpec = openjceplusKeyFactory.getKeySpec(openjceplusPrivateKey, interopPrivKeySpec.getClass());
        System.out.println(1/0);
        assertEquals(interopPrivKeySpec.getClass(), keySpec.getClass());
        assertPrivateKeyPKCS8SpecEquals(interopPrivKeySpec, keySpec);
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testMLDSAGetKeySpecPrivateInteropToPlus(String algorithm)
            throws Exception {
        // This is not in the FIPS provider yet.
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        // This test is for SunJCE/OpenJCEPlus interop, not BC.
        // assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName2()));

        KeyFactory openjceplusKeyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        KeyPairGenerator interopKpg = KeyPairGenerator.getInstance(algorithm, getInteropProviderName2());
        KeyPair interopKeyPair = interopKpg.generateKeyPair();
        PrivateKey interopPrivateKey = interopKeyPair.getPrivate();
        KeySpec interopPrivKeySpec = new PKCS8EncodedKeySpec(interopPrivateKey.getEncoded());
        PrivateKey openjceplusPrivateKey = openjceplusKeyFactory.generatePrivate(interopPrivKeySpec);

        Signature signerPlus = Signature.getInstance(algorithm, getProviderName());
        signerPlus.initSign(openjceplusPrivateKey);
        signerPlus.update(origMsg);
        byte[] signaturePlus = signerPlus.sign();

        Signature verifierInterop = Signature.getInstance(algorithm, getInteropProviderName2());
        verifierInterop.initVerify(interopKeyPair.getPublic());
        verifierInterop.update(origMsg);
        System.out.println(1/0);
        assertTrue(verifierInterop.verify(signaturePlus), "Signature verification failed");
    }

    private void assertPrivateKeyPKCS8SpecEquals(KeySpec expected, KeySpec actual) {
        assertEquals(PKCS8EncodedKeySpec.class, actual.getClass());

        PKCS8EncodedKeySpec expectedSpec = (PKCS8EncodedKeySpec) expected;
        PKCS8EncodedKeySpec actualSpec = (PKCS8EncodedKeySpec) actual;

        assertArrayEquals(expectedSpec.getEncoded(), actualSpec.getEncoded());
        assertEquals(expectedSpec.getAlgorithm(), actualSpec.getAlgorithm());
        assertEquals(expectedSpec.getFormat(), actualSpec.getFormat());
    }

    @ParameterizedTest
    @CsvSource({
            "ML-DSA-44, RFC9881_ML_DSA_44_PRIVATE_KEY_SEED,     RFC9881_ML_DSA_44_PUBLIC_KEY",
            "ML-DSA-44, RFC9881_ML_DSA_44_PRIVATE_KEY_EXPANDED, RFC9881_ML_DSA_44_PUBLIC_KEY",
            "ML-DSA-44, RFC9881_ML_DSA_44_PRIVATE_KEY_BOTH,     RFC9881_ML_DSA_44_PUBLIC_KEY",

            "ML-DSA-65, RFC9881_ML_DSA_65_PRIVATE_KEY_SEED,     RFC9881_ML_DSA_65_PUBLIC_KEY",
            "ML-DSA-65, RFC9881_ML_DSA_65_PRIVATE_KEY_EXPANDED, RFC9881_ML_DSA_65_PUBLIC_KEY",
            "ML-DSA-65, RFC9881_ML_DSA_65_PRIVATE_KEY_BOTH,     RFC9881_ML_DSA_65_PUBLIC_KEY",

            "ML-DSA-87, RFC9881_ML_DSA_87_PRIVATE_KEY_SEED,     RFC9881_ML_DSA_87_PUBLIC_KEY",
            "ML-DSA-87, RFC9881_ML_DSA_87_PRIVATE_KEY_EXPANDED, RFC9881_ML_DSA_87_PUBLIC_KEY",
            "ML-DSA-87, RFC9881_ML_DSA_87_PRIVATE_KEY_BOTH,     RFC9881_ML_DSA_87_PUBLIC_KEY",
    })
    public void testRFC9881MLDSAKeyFactorySignVerify(String algorithm,
            String privateKeyName, String publicKeyName) throws Exception {

        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName2()));

        KeyFactory sunKeyFactory = KeyFactory.getInstance(algorithm, getInteropProviderName2());
        KeyFactory openjceplusKeyFactory = KeyFactory.getInstance(algorithm, getProviderName());

        byte[] rfcPrivateKeyEncoded = decodePEM(getRFCPrivateKeyPEM(privateKeyName));
        byte[] rfcPublicKeyEncoded = decodePEM(getRFCPublicKeyPEM(publicKeyName));

        // PrivateKey sunPrivateKey = sunKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(rfcPrivateKeyEncoded));
        // PKCS8EncodedKeySpec sunPrivateKeySpec = sunKeyFactory.getKeySpec(sunPrivateKey, PKCS8EncodedKeySpec.class);
        // rivateKey openjceplusPrivateKey = openjceplusKeyFactory.generatePrivate(sunPrivateKeySpec);
        PrivateKey openjceplusPrivateKey = openjceplusKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(rfcPrivateKeyEncoded));
        PublicKey sunPublicKey = sunKeyFactory.generatePublic(new X509EncodedKeySpec(rfcPublicKeyEncoded));

        Signature signer = Signature.getInstance(algorithm, getProviderName());
        signer.initSign(openjceplusPrivateKey);
        signer.update(origMsg);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance(algorithm, getInteropProviderName2());
        verifier.initVerify(sunPublicKey);
        verifier.update(origMsg);

        assertTrue(verifier.verify(signature));
    }

    @ParameterizedTest
    @CsvSource({
            "ML-KEM-512,  RFC9935_ML_KEM_512_PRIVATE_KEY_SEED,      RFC9935_ML_KEM_512_PUBLIC_KEY",
            "ML-KEM-512,  RFC9935_ML_KEM_512_PRIVATE_KEY_EXPANDED,  RFC9935_ML_KEM_512_PUBLIC_KEY",
            "ML-KEM-512,  RFC9935_ML_KEM_512_PRIVATE_KEY_BOTH,      RFC9935_ML_KEM_512_PUBLIC_KEY",
            "ML-KEM-768,  RFC9935_ML_KEM_768_PRIVATE_KEY_SEED,      RFC9935_ML_KEM_768_PUBLIC_KEY",
            "ML-KEM-768,  RFC9935_ML_KEM_768_PRIVATE_KEY_EXPANDED,  RFC9935_ML_KEM_768_PUBLIC_KEY",
            "ML-KEM-768,  RFC9935_ML_KEM_768_PRIVATE_KEY_BOTH,      RFC9935_ML_KEM_768_PUBLIC_KEY",
            "ML-KEM-1024, RFC9935_ML_KEM_1024_PRIVATE_KEY_SEED,     RFC9935_ML_KEM_1024_PUBLIC_KEY",
            "ML-KEM-1024, RFC9935_ML_KEM_1024_PRIVATE_KEY_EXPANDED, RFC9935_ML_KEM_1024_PUBLIC_KEY",
            "ML-KEM-1024, RFC9935_ML_KEM_1024_PRIVATE_KEY_BOTH,     RFC9935_ML_KEM_1024_PUBLIC_KEY",
    })
    public void testRFC9935MLKEMKeyFactoryEncapsulateDecapsulate(String algorithm,
        String privateKeyName, String publicKeyName) throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(Utils.PROVIDER_BC.equals(getInteropProviderName2()));

        KeyFactory sunjceKeyFactory = KeyFactory.getInstance(algorithm, getInteropProviderName());
        KeyFactory openjceplusKeyFactory = KeyFactory.getInstance(algorithm, getProviderName());

        byte[] rfcPrivateKeyEncoded = decodePEM(getRFCPrivateKeyPEM(privateKeyName));
        byte[] rfcPublicKeyEncoded = decodePEM(getRFCPublicKeyPEM(publicKeyName));

        PrivateKey openjceplusPrivateKey = openjceplusKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(rfcPrivateKeyEncoded));

        PublicKey sunjcePublicKey = sunjceKeyFactory.generatePublic(new X509EncodedKeySpec(rfcPublicKeyEncoded));

        KEM sunjceKEM = KEM.getInstance(algorithm, getInteropProviderName());
        KEM.Encapsulator encapsulator = sunjceKEM.newEncapsulator(sunjcePublicKey);

        KEM.Encapsulated encapsulated = encapsulator.encapsulate();

        KEM openjceplusKEM = KEM.getInstance(algorithm, getProviderName());
        KEM.Decapsulator decapsulator = openjceplusKEM.newDecapsulator(openjceplusPrivateKey);

        SecretKey decapsulatedSecret = decapsulator.decapsulate(encapsulated.encapsulation());

        assertArrayEquals(encapsulated.key().getEncoded(),
                decapsulatedSecret.getEncoded());
    }

    private static String getRFCPrivateKeyPEM(String name) {
        if ("RFC9881_ML_DSA_44_PRIVATE_KEY_SEED".equals(name)) {
            return RFC9881_ML_DSA_44_PRIVATE_KEY_SEED;
        }
        if ("RFC9881_ML_DSA_44_PRIVATE_KEY_EXPANDED".equals(name)) {
            return RFC9881_ML_DSA_44_PRIVATE_KEY_EXPANDED;
        }
        if ("RFC9881_ML_DSA_44_PRIVATE_KEY_BOTH".equals(name)) {
            return RFC9881_ML_DSA_44_PRIVATE_KEY_BOTH;
        }
        if ("RFC9881_ML_DSA_65_PRIVATE_KEY_SEED".equals(name)) {
            return RFC9881_ML_DSA_65_PRIVATE_KEY_SEED;
        }
        if ("RFC9881_ML_DSA_65_PRIVATE_KEY_EXPANDED".equals(name)) {
            return RFC9881_ML_DSA_65_PRIVATE_KEY_EXPANDED;
        }
        if ("RFC9881_ML_DSA_65_PRIVATE_KEY_BOTH".equals(name)) {
            return RFC9881_ML_DSA_65_PRIVATE_KEY_BOTH;
        }
        if ("RFC9881_ML_DSA_87_PRIVATE_KEY_SEED".equals(name)) {
            return RFC9881_ML_DSA_87_PRIVATE_KEY_SEED;
        }
        if ("RFC9881_ML_DSA_87_PRIVATE_KEY_EXPANDED".equals(name)) {
            return RFC9881_ML_DSA_87_PRIVATE_KEY_EXPANDED;
        }
        if ("RFC9881_ML_DSA_87_PRIVATE_KEY_BOTH".equals(name)) {
            return RFC9881_ML_DSA_87_PRIVATE_KEY_BOTH;
        }
        if ("RFC9935_ML_KEM_512_PRIVATE_KEY_SEED".equals(name)) {
            return RFC9935_ML_KEM_512_PRIVATE_KEY_SEED;
        }
        if ("RFC9935_ML_KEM_512_PRIVATE_KEY_EXPANDED".equals(name)) {
            return RFC9935_ML_KEM_512_PRIVATE_KEY_EXPANDED;
        }
        if ("RFC9935_ML_KEM_512_PRIVATE_KEY_BOTH".equals(name)) {
            return RFC9935_ML_KEM_512_PRIVATE_KEY_BOTH;
        }
        if ("RFC9935_ML_KEM_768_PRIVATE_KEY_SEED".equals(name)) {
            return RFC9935_ML_KEM_768_PRIVATE_KEY_SEED;
        }
        if ("RFC9935_ML_KEM_768_PRIVATE_KEY_EXPANDED".equals(name)) {
            return RFC9935_ML_KEM_768_PRIVATE_KEY_EXPANDED;
        }
        if ("RFC9935_ML_KEM_768_PRIVATE_KEY_BOTH".equals(name)) {
            return RFC9935_ML_KEM_768_PRIVATE_KEY_BOTH;
        }
        if ("RFC9935_ML_KEM_1024_PRIVATE_KEY_SEED".equals(name)) {
            return RFC9935_ML_KEM_1024_PRIVATE_KEY_SEED;
        }
        if ("RFC9935_ML_KEM_1024_PRIVATE_KEY_EXPANDED".equals(name)) {
            return RFC9935_ML_KEM_1024_PRIVATE_KEY_EXPANDED;
        }
        if ("RFC9935_ML_KEM_1024_PRIVATE_KEY_BOTH".equals(name)) {
            return RFC9935_ML_KEM_1024_PRIVATE_KEY_BOTH;
        }

        return null;
    }

    private static String getRFCPublicKeyPEM(String name) {
        if ("RFC9881_ML_DSA_44_PUBLIC_KEY".equals(name)) {
            return RFC9881_ML_DSA_44_PUBLIC_KEY;
        }
        if ("RFC9881_ML_DSA_65_PUBLIC_KEY".equals(name)) {
            return RFC9881_ML_DSA_65_PUBLIC_KEY;
        }
        if ("RFC9881_ML_DSA_87_PUBLIC_KEY".equals(name)) {
            return RFC9881_ML_DSA_87_PUBLIC_KEY;
        }
        if ("RFC9935_ML_KEM_512_PUBLIC_KEY".equals(name)) {
            return RFC9935_ML_KEM_512_PUBLIC_KEY;
        }
        if ("RFC9935_ML_KEM_768_PUBLIC_KEY".equals(name)) {
            return RFC9935_ML_KEM_768_PUBLIC_KEY;
        }
        if ("RFC9935_ML_KEM_1024_PUBLIC_KEY".equals(name)) {
            return RFC9935_ML_KEM_1024_PUBLIC_KEY;
        }

        return null;
    }

    private static byte[] decodePEM(String pem) {
        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }
}
