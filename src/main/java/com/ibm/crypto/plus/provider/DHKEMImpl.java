/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import javax.crypto.KEMSpi;

import com.google.common.collect.Tables;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public final class DHKEMImpl implements KEMSpi {

  public DHKEM() {}

  @Override
  public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey,
                                               AlgorithmParameterSpec spec,
                                               SecureRandom secureRandom)
    	throws InvalidKeyException, InvalidAlgorithmParameterException {
    Params params = Params.fromKey(publicKey);     // 解析曲线/哈希/长度
    SecureRandom rng = (sr != null) ? sr : getDefaultSR();
    return new Handler(params, /*skR=*/null, pkR, rng);
  }

  @Override
  public DecapsulatorSpi engineNewDecapsulator(PrivateKey skR,
                                               AlgorithmParameterSpec spec)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    Params params = Params.fromKey(skR);     // 与上同源
    return new Handler(params, skR, /*pkR=*/null, getDefaultSR());
  }

  private static SecureRandom getDefaultSR() {
    return com.ibm.crypto.plus.provider.Util.getSecureRandom(); // 复用现有工具
  }

  // --- Handler 同时实现 Encap/Decap ---
  static final class Handler extends EncapsulatorSpi implements DecapsulatorSpi {
    final Params params;
    final PrivateKey skR; // may be null
    final PublicKey  pkR; // may be null
    final SecureRandom rng;

    Handler(Params p, PrivateKey skR, PublicKey pkR, SecureRandom rng) {
      this.params = p; this.skR = skR; this.pkR = pkR; this.rng = rng;
    }

    // Encap：返回 (sharedSecret, enc)
    @Override
    public Result encapsulate() throws GeneralSecurityException {
      KeyPair kpE = params.generateEphemeral(rng);
      byte[] enc = params.serializePublic(kpE.getPublic());
      PublicKey pkR0 = (pkR != null) ? pkR : params.recoverPublicFromPrivate(skR);
      byte[] dh = params.dh(kpE.getPrivate(), pkR0);     // ECDH/XDH
      byte[] kemCtx = params.kemContext(enc, params.serializePublic(pkR0), /*opt pkS=*/null);
      byte[] ss = params.extractAndExpand(dh, kemCtx);   // Labeled HKDF
      return new Result(ss, enc);
    }

    // Decap：输入 enc，返回 sharedSecret
    @Override
    public byte[] decapsulate(byte[] enc) throws GeneralSecurityException {
      PublicKey pkE = params.parsePeerPublic(enc);
      byte[] dh = params.dh(skR, pkE);
      PublicKey pkR0 = params.recoverPublicFromPrivate(skR);
      byte[] kemCtx = params.kemContext(enc, params.serializePublic(pkR0), /*opt pkS=*/null);
      return params.extractAndExpand(dh, kemCtx);
    }
  }

  // --- Params：把套件常量/算法选择装起来 ---
  static final class Params {
    final int kemId;            // 0x0010/11/12/20/21
    final String kaAlg;         // "ECDH" / "XDH"
    final String hkdfAlg;       // "HKDFwithSHA256/384/512"（或内部别名）
    final int Nsecret, Npk;     // 输出长度/enc 长度
    final AlgorithmParameterSpec ecSpecOrNull;

    static Params fromKey(Key k) throws InvalidKeyException {
      // 读取曲线/类型，映射到 kemId/hkdfAlg/Nsecret/Npk...
      // 对 EC：解析 ECParameterSpec；对 XEC：识别 X25519/X448
      return Tables.map(k);
    }

    KeyPair generateEphemeral(SecureRandom rng) throws GeneralSecurityException {
      // EC: ECGenParameterSpec( "secp256r1" | "secp384r1" | "secp521r1" )
      // XDH: "X25519" | "X448"
      // 用 Provider 自带 KPG，确保落在 FIPS 边界内
    }

    byte[] dh(PrivateKey sk, PublicKey pk) throws GeneralSecurityException {
      // 直接复用 Provider 已有的 ECDH/XDH KeyAgreement 实现
      // 并检测 "全零共享"（X25519/X448），异常化处理
    }

    byte[] serializePublic(PublicKey pk) throws GeneralSecurityException {
      // EC -> SEC1 uncompressed: 0x04||X||Y
      // X25519/X448 -> 定长 u 坐标字节（32/56）
    }

    PublicKey parsePeerPublic(byte[] enc) throws GeneralSecurityException {
      // 反序列化 enc 到相应曲线的 PublicKey（注意点验证/参数绑定）
    }

    PublicKey recoverPublicFromPrivate(PrivateKey sk) throws GeneralSecurityException {
      // 若私钥对象已含公钥/参数，直接导出；否则走低层 API 重建（PKCS#11 场景要小心）
    }

    byte[] kemContext(byte[] enc, byte[] pkRm, byte[] pkSmOrNull) {
      // kem_context = enc || pkRm [|| pkSm]（auth 模式留扩展点）
    }

    byte[] extractAndExpand(byte[] dh, byte[] kemCtx) throws GeneralSecurityException {
      // LabeledExtract / LabeledExpand：见下一节
    }
  }
}
