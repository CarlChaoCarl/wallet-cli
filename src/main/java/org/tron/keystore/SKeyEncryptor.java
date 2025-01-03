package org.tron.keystore;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.KeyParameter;
import org.tron.common.crypto.Hash;
import org.tron.common.crypto.Sha256Sm3Hash;
import org.tron.common.utils.ByteArray;
import org.tron.core.exception.CipherException;
import org.tron.walletserver.WalletApi;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;

// 完整的加密和解密流程，包括生成加密密钥、加密和解密操作、以及密码验证等功能。
public class SKeyEncryptor {

  private static final int N_LIGHT = 1 << 12;
  private static final int P_LIGHT = 6;

  private static final int N_STANDARD = 1 << 18;
  private static final int P_STANDARD = 1;

  private static final int R = 8;
  private static final int DKLEN = 32;

  private static final int CURRENT_VERSION = 3;

  private static final String CIPHER = "aes-128-ctr";
  static final String AES_128_CTR = "pbkdf2";
  static final String SCRYPT = "scrypt";

  //- 该方法用于创建加密密钥。
  //- 生成一个随机的盐值。
  //- 通过  generateDerivedScryptKey  方法生成派生密钥。
  //- 从派生密钥中提取加密密钥。
  //- 生成一个随机的初始化向量（IV）。
  //- 使用  performCipherOperation  方法对密钥进行加密，得到密文。
  //- 生成消息认证码（MAC）以确保数据完整性。
  //- 通过  createSkey  方法创建并返回一个  SKeyCapsule  对象。
  public static SKeyCapsule create(byte[] password, byte[] skey, int n, int p)
      throws CipherException {

    byte[] salt = generateRandomBytes(32);

    byte[] derivedKey = generateDerivedScryptKey(password, salt, n, R, p, DKLEN);

    byte[] encryptKey = Arrays.copyOfRange(derivedKey, 0, 16);
    byte[] iv = generateRandomBytes(16);

    byte[] cipherText = performCipherOperation(Cipher.ENCRYPT_MODE, iv, encryptKey,
        skey);

    byte[] mac = generateMac(derivedKey, cipherText);

    byte[] fp = Arrays.copyOfRange(Sha256Sm3Hash.hash(skey), 0, 4);

    return createSkey(fp, cipherText, iv, salt, mac, n, p);
  }

  // -  createStandard  用于创建标准的加密密钥。
  public static SKeyCapsule createStandard(byte[] password, byte[] skey)
      throws CipherException {
    return create(password, skey, N_STANDARD, P_STANDARD);
  }

  // -  createLight  用于创建轻量级的加密密钥。
  public static SKeyCapsule createLight(byte[] password, byte[] skey)
      throws CipherException {
    return create(password, skey, N_LIGHT, P_LIGHT);
  }
  // - 该方法用于创建并返回一个  SKeyCapsule  对象。
  // - 设置指纹、加密信息、加密参数、密钥派生函数参数、MAC 等信息。
  private static SKeyCapsule createSkey(
      byte[] fp, byte[] cipherText, byte[] iv, byte[] salt, byte[] mac,
      int n, int p) {

    SKeyCapsule skey = new SKeyCapsule();
    skey.setFp(WalletApi.encode58Check(fp));

    SKeyCapsule.Crypto crypto = new SKeyCapsule.Crypto();
    crypto.setCipher(CIPHER);
    crypto.setCiphertext(ByteArray.toHexString(cipherText));
    skey.setCrypto(crypto);

    SKeyCapsule.CipherParams cipherParams = new SKeyCapsule.CipherParams();
    cipherParams.setIv(ByteArray.toHexString(iv));
    crypto.setCipherparams(cipherParams);

    crypto.setKdf(SCRYPT);
    SKeyCapsule.ScryptKdfParams kdfParams = new SKeyCapsule.ScryptKdfParams();
    kdfParams.setDklen(DKLEN);
    kdfParams.setN(n);
    kdfParams.setP(p);
    kdfParams.setR(R);
    kdfParams.setSalt(ByteArray.toHexString(salt));
    crypto.setKdfparams(kdfParams);

    crypto.setMac(ByteArray.toHexString(mac));
    skey.setCrypto(crypto);
    skey.setId(UUID.randomUUID().toString());
    skey.setVersion(CURRENT_VERSION);

    return skey;
  }

  // - 使用  SCrypt  算法生成派生密钥。
  private static byte[] generateDerivedScryptKey(
      byte[] password, byte[] salt, int n, int r, int p, int dkLen) {
    return SCrypt.generate(password, salt, n, r, p, dkLen);
  }


  private static byte[] generateAes128CtrDerivedKey(
      byte[] password, byte[] salt, int c, String prf) throws CipherException {

    if (!prf.equals("hmac-sha256")) {
       throw new CipherException("Unsupported prf:" + prf);
    }

    // Java 8 supports this, but you have to convert the password to a character array, see
    // http://stackoverflow.com/a/27928435/3211687

    PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
    gen.init(password, salt, c);
    return ((KeyParameter) gen.generateDerivedParameters(256)).getKey();
  }

  // - 使用 AES-128-CTR 算法执行加密或解密操作。
  private static byte[] performCipherOperation(
      int mode, byte[] iv, byte[] encryptKey, byte[] text) throws CipherException {

    try {
      IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
      Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

      SecretKeySpec secretKeySpec = new SecretKeySpec(encryptKey, "AES");
      cipher.init(mode, secretKeySpec, ivParameterSpec);
      return cipher.doFinal(text);
    } catch (NoSuchPaddingException | NoSuchAlgorithmException
        | InvalidAlgorithmParameterException | InvalidKeyException
        | BadPaddingException | IllegalBlockSizeException e) {
      throw new CipherException("Error performing cipher operation", e);
    }
  }

  // - 生成消息认证码（MAC）以确保数据的完整性。
  private static byte[] generateMac(byte[] derivedKey, byte[] cipherText) {
    byte[] result = new byte[16 + cipherText.length];

    System.arraycopy(derivedKey, 16, result, 0, 16);
    System.arraycopy(cipherText, 0, result, 16, cipherText.length);

    return Hash.sha3(result);
  }

  // - 该方法用于解密私钥。
  // - 验证 SKeyCapsule 对象的完整性和正确性。
  // - 根据密钥派生函数参数生成派生密钥。
  // - 验证 MAC。
  // - 执行解密操作以获取私钥。
  public static byte[] decrypt2PrivateBytes(byte[] password, SKeyCapsule skey)
      throws CipherException {

    validate(skey);

    SKeyCapsule.Crypto crypto = skey.getCrypto();

    byte[] mac = ByteArray.fromHexString(crypto.getMac());
    byte[] iv = ByteArray.fromHexString(crypto.getCipherparams().getIv());
    byte[] cipherText = ByteArray.fromHexString(crypto.getCiphertext());

    byte[] derivedKey;

    SKeyCapsule.KdfParams kdfParams = crypto.getKdfparams();
    if (kdfParams instanceof SKeyCapsule.ScryptKdfParams) {
      SKeyCapsule.ScryptKdfParams scryptKdfParams =
          (SKeyCapsule.ScryptKdfParams) crypto.getKdfparams();
      int dklen = scryptKdfParams.getDklen();
      int n = scryptKdfParams.getN();
      int p = scryptKdfParams.getP();
      int r = scryptKdfParams.getR();
      byte[] salt = ByteArray.fromHexString(scryptKdfParams.getSalt());
      derivedKey = generateDerivedScryptKey(password, salt, n, r, p, dklen);
    } else if (kdfParams instanceof SKeyCapsule.Aes128CtrKdfParams) {
      SKeyCapsule.Aes128CtrKdfParams aes128CtrKdfParams =
          (SKeyCapsule.Aes128CtrKdfParams) crypto.getKdfparams();
      int c = aes128CtrKdfParams.getC();
      String prf = aes128CtrKdfParams.getPrf();
      byte[] salt = ByteArray.fromHexString(aes128CtrKdfParams.getSalt());

      derivedKey = generateAes128CtrDerivedKey(password, salt, c, prf);
    } else {
      throw new CipherException("Unable to deserialize params: " + crypto.getKdf());
    }

    byte[] derivedMac = generateMac(derivedKey, cipherText);

    if (!Arrays.equals(derivedMac, mac)) {
      throw new CipherException("Invalid password provided");
    }

    byte[] encryptKey = Arrays.copyOfRange(derivedKey, 0, 16);
    StringUtils.clear(derivedKey);
    byte[] privateKey = performCipherOperation(Cipher.DECRYPT_MODE, iv, encryptKey, cipherText);
    StringUtils.clear(encryptKey);

    return privateKey;
  }

  // - 验证提供的密码是否正确。
  // - 验证 MAC 以确保密码正确。
  public static boolean validPassword(byte[] password, SKeyCapsule skey)
      throws CipherException {

    validate(skey);

    SKeyCapsule.Crypto crypto = skey.getCrypto();

    byte[] mac = ByteArray.fromHexString(crypto.getMac());
    byte[] cipherText = ByteArray.fromHexString(crypto.getCiphertext());

    byte[] derivedKey;

    SKeyCapsule.KdfParams kdfParams = crypto.getKdfparams();
    if (kdfParams instanceof SKeyCapsule.ScryptKdfParams) {
      SKeyCapsule.ScryptKdfParams scryptKdfParams =
          (SKeyCapsule.ScryptKdfParams) crypto.getKdfparams();
      int dklen = scryptKdfParams.getDklen();
      int n = scryptKdfParams.getN();
      int p = scryptKdfParams.getP();
      int r = scryptKdfParams.getR();
      byte[] salt = ByteArray.fromHexString(scryptKdfParams.getSalt());
      derivedKey = generateDerivedScryptKey(password, salt, n, r, p, dklen);
    } else if (kdfParams instanceof SKeyCapsule.Aes128CtrKdfParams) {
      SKeyCapsule.Aes128CtrKdfParams aes128CtrKdfParams =
          (SKeyCapsule.Aes128CtrKdfParams) crypto.getKdfparams();
      int c = aes128CtrKdfParams.getC();
      String prf = aes128CtrKdfParams.getPrf();
      byte[] salt = ByteArray.fromHexString(aes128CtrKdfParams.getSalt());

      derivedKey = generateAes128CtrDerivedKey(password, salt, c, prf);
    } else {
      throw new CipherException("Unable to deserialize params: " + crypto.getKdf());
    }

    byte[] derivedMac = generateMac(derivedKey, cipherText);
    StringUtils.clear(derivedKey);
    if (!Arrays.equals(derivedMac, mac)) {
      throw new CipherException("Invalid password provided");
    }

    return true;
  }

  // - 验证 SKeyCapsule 对象的版本、加密算法和密钥派生函数类型。
  static void validate(SKeyCapsule skey) throws CipherException {
    SKeyCapsule.Crypto crypto = skey.getCrypto();

    if (skey.getVersion() != CURRENT_VERSION) {
      throw new CipherException("Wallet version is not supported");
    }

    if (!crypto.getCipher().equals(CIPHER)) {
      throw new CipherException("Wallet cipher is not supported");
    }

    if (!crypto.getKdf().equals(AES_128_CTR) && !crypto.getKdf().equals(SCRYPT)) {
      throw new CipherException("KDF type is not supported");
    }
  }

  // - 生成指定大小的随机字节数组。
  public static byte[] generateRandomBytes(int size) {
    byte[] bytes = new byte[size];
    new SecureRandom().nextBytes(bytes);
    return bytes;
  }

}
