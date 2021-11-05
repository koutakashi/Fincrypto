// Licensed Materials - Property of IBM
// 6949-XXX:Encryption and Key Management API for Financial Institutions
// Copyright IBM Japan, Ltd. 2017 All Rights Reserved.
//
// DISCLAIMER OF WARRANTIES:
// The following code is a sample code created by IBM Japan, Ltd.
// This sample code is not part of any standard IBM product and is provided
// to you solely for the purpose of assisting you in the development of
// your applications. The code is provided "AS IS", without warranty of
// any kind. IBM shall not be liable for any damages arising out of your
// use of the sample code, even if they have been advised of the
// possibility of such damages.
package com.ibm.fincrypto.sample;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import com.ibm.fincrypto.sample.key.KeyInfo;

/**
 * 暗号化鍵として使用するAES鍵による暗号化機能を提供するクラスです。AES鍵はRSA公開鍵で暗号化されて、 暗号化データと共にRSA秘密鍵を保有するユーザーに送られます。 AES鍵の鍵長はクラス変数
 * <code>AES_KEY_LENGTH</code> に定義します。
 * AESの鍵長は、アメリカ合衆国の輸出規制に従い、デフォルトでバンドルされているJavaでは使用できる暗号化鍵のサイズに制限があります。128bitより大きい鍵長を指定する場合、バンドルされている暗号化ポリシー・ファイルを
 * Java提供元が発行する無制限JCEポリシー・ ファイルで置き換える必要があります。
 * 
 * @version 1.00, 2017/08/31
 * @since 1.00
 */
public class RSAEncryptor {

    /**
     * AESの鍵長
     */
    private static final int AES_KEY_LENGTH = 128;
    /**
     * AESのブロック長
     */
    private static final int BLOCK_LENGTH_AES = 16;
    /**
     * RSA公開鍵
     */
    private final KeyInfo keyInfo;
    /**
     * AES暗号化鍵
     */
    private SecretKey aesKey = null;

    /**
     * コンストラクタ。RSA公開鍵情報を引数に渡して呼び出します。
     * 
     * @param keyInfo RSA公開鍵情報
     * @throws IllegalArgumentException 引数に<code>null</code>が指定された場合
     * @since 1.00
     */
    public RSAEncryptor(KeyInfo keyInfo) throws IllegalArgumentException {
        if (keyInfo == null) {
            throw new IllegalArgumentException("keyInfo must be not null.");
        }
        this.keyInfo = keyInfo;
    }

    /**
     * AES暗号化を実行します。
     * 
     * @param plainText 暗号化を行うデータ(平文)
     * @param initVct 初期化ベクトル (nullの場合は、当メソッド内でメッセージ・ダイジェストを作成し、先頭16バイトを初期化ベクトルとして扱う)
     * @return AES暗号化結果データ
     * @throws GeneralSecurityException AES暗号化、RSA暗号化、もしくはハッシュ値計算で例外がスローされた場合
     * @throws IllegalArgumentException 平文に<code>null</code>もしくは長さ0の文字列が指定された場合
     * @since 1.00
     */
    public EncryptionOutputData encryptData(String plainText, byte[] initVct)
            throws GeneralSecurityException, IllegalArgumentException {
        if (plainText == null || plainText.length() == 0) {
            throw new IllegalArgumentException("plainText must have one and more length.");
        }
        if (aesKey == null) {
            // AES鍵が未生成の場合は生成します
            aesKey = generateAESSessionKey();
        }
        byte[] plainBin = plainText.getBytes(StandardCharsets.UTF_8);
        EncryptionOutputData outData = new EncryptionOutputData();
        // 初期化ベクトルを結果データに設定
        outData.setInitialVector(getInitialVector(plainBin, initVct));

        // RSA公開鍵により、AES暗号化キーを暗号化して結果データに設定
        outData.setEncryptedKey(encryptWithRSA(aesKey.getEncoded()));

        // AES暗号化を実施して結果データに設定
        outData.setCipherText(encryptWithAES(plainBin, new IvParameterSpec(outData.getInitialVector())));

        return outData;
    }

    /**
     * AES暗号化用の暗号化鍵を生成します。
     * 
     * @return AES暗号化鍵
     * @throws GeneralSecurityException 鍵の生成処理で例外がスローされた場合
     */
    private SecretKey generateAESSessionKey() throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(AES_KEY_LENGTH);
        return generator.generateKey();
    }

    /**
     * 引数に指定された初期化ベクトルが<code>null</code>の場合は暗号化対象データのハッシュ値を初期化ベクトルとして返します。
     * 
     * @param data 暗号化対象のデータ
     * @param initVct 初期化ベクトル
     * @return 補正された初期化ベクトル
     * @throws GeneralSecurityException ハッシュ値の処理で例外がスローされた場合
     * @since 1.00
     */
    private byte[] getInitialVector(byte[] data, byte[] initVct) throws GeneralSecurityException {
        byte[] result = initVct;
        if (null == initVct) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            result = Arrays.copyOf(md.digest(data), BLOCK_LENGTH_AES);
        }
        return result;
    }

    /**
     * 引数のデータをRSA公開鍵で暗号化します。
     * 
     * @param data 暗号化対象のデータ
     * @return 暗号化されたデータ
     * @throws GeneralSecurityException 公開鍵の処理で例外がスローされた場合
     * @since 1.00
     */
    private byte[] encryptWithRSA(byte[] data) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyInfo.getPublicKey());
        return cipher.doFinal(data);
    }

    /**
     * 引数のデータをAES暗号化鍵で暗号化します。
     * 
     * @param data 暗号化対象のデータ
     * @param iv 初期化ベクトル
     * @return 暗号化されたデータ
     * @throws GeneralSecurityException 暗号化の処理で例外がスローされた場合
     * @since 1.00
     */
    private byte[] encryptWithAES(byte[] data, IvParameterSpec iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
        // AES暗号化実施
        return cipher.doFinal(data);
    }

    /**
     * AES暗号化鍵を取得します。
     * 
     * @return AES暗号化鍵
     * @since 1.00
     */
    public SecretKey getAESSessionKey() {
        return aesKey;
    }

}
