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
package com.ibm.fincrypto.sample.client;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.ibm.fincrypto.sample.EncryptionOutputData;
import com.ibm.fincrypto.sample.RSAEncryptor;
import com.ibm.fincrypto.sample.key.KeyInfo;
import com.ibm.fincrypto.sample.key.KeyStoreKeyInfo;
import com.ibm.fincrypto.sample.key.PKCS8KeyInfo;
import com.ibm.fincrypto.sample.key.PairValueKeyInfo;

/**
 * 暗号化APIを使用するクライアント側のサンプルを提供するクラスです。
 * 
 * @version 1.00, 2017/08/31
 * @since 1.00
 */
public class Client {

    /**
     * メイン関数。3種類の形式のRSA公開鍵を使用して、暗号化鍵による暗号化/復号を実行します。
     * 
     * @since 1.00
     */
    public static void main(String[] args) throws Exception {
        Client client = new Client();
        Alice alice = new Alice();

        System.out.println("**** 16進数文字列表現のRSA公開鍵を使用するケース ****");
        EncryptionOutputData outData = client.processHexStrPublicKey();
        System.out.println(">>>> 復号結果 :");
        System.out.println("decrypt data = " + new String(alice.decrypt(outData), StandardCharsets.UTF_8));
        System.out.println("");

        System.out.println("**** キーストアに格納されたRSA公開鍵を使用するケース ****");
        outData = client.processKeyStorePublicKey();
        System.out.println(">>>> 復号結果 :");
        System.out.println("decrypt data = " + new String(alice.decrypt(outData), StandardCharsets.UTF_8));
        System.out.println("");

        System.out.println("**** PKCS#8 DER形式のRSA公開鍵を使用するケース ****");
        outData = client.processPKCS8PublicKey();
        System.out.println(">>>> 復号結果 :");
        System.out.println("decrypt data = " + new String(alice.decrypt(outData), StandardCharsets.UTF_8));
        System.out.println("");
    }

    /**
     * 16進数文字列表現のRSA公開鍵情報を使用して暗号化を行います。
     * 
     * @return 暗号化結果データ
     * @throws IOException ファイルの入出力で例外がスローされた場合
     * @throws GeneralSecurityException 暗号化処理で例外がスローされた場合
     * @since 1.00
     */
    public EncryptionOutputData processHexStrPublicKey() throws IOException, GeneralSecurityException {
        byte[] bytes = Files.readAllBytes(new File("pubkey_hexstr.txt").toPath());
        String[] values = new String(bytes, StandardCharsets.UTF_8).split("&");
        KeyInfo keyInfo = new PairValueKeyInfo(values[0], values[1]);
        String plainText = "123456789012";

        return processEncryption(keyInfo, plainText);
    }

    /**
     * キーストアに格納されたRSA公開鍵情報を使用して暗号化を行います。
     * 
     * @return 暗号化結果データ
     * @throws GeneralSecurityException 暗号化処理で例外がスローされた場合
     * @since 1.00
     */
    public EncryptionOutputData processKeyStorePublicKey() throws GeneralSecurityException {
        final String alias = "alice";
        final String keyStoreType = "JCEKS";
        final String keyStoreFilePath = "bob.jck";
        final String keyStorePassword = "bobpass";
        KeyInfo keyInfo = new KeyStoreKeyInfo(alias, keyStoreType, keyStoreFilePath, keyStorePassword);
        String plainText = "This is a test.";

        return processEncryption(keyInfo, plainText);
    }

    /**
     * PKCS#8 DER形式のRSA公開鍵情報を使用して暗号化を行います。
     * 
     * @return 暗号化結果データ
     * @throws GeneralSecurityException 暗号化処理で例外がスローされた場合
     * @since 1.00
     */
    public EncryptionOutputData processPKCS8PublicKey() throws GeneralSecurityException {
        final String keyFilename = "alice.der";
        KeyInfo keyInfo = new PKCS8KeyInfo(keyFilename);
        String plainText = "これはテストです。";

        return processEncryption(keyInfo, plainText);
    }

    /**
     * 引数に指定されたRSA公開鍵情報を使用して、初期化ベクトルは指定なしで暗号化を行います。
     * 
     * @param keyInfo RSA公開鍵情報
     * @param plainText 平文
     * @return 暗号化結果データ
     * @throws GeneralSecurityException 暗号化処理で例外がスローされた場合
     * @since 1.00
     */
    private EncryptionOutputData processEncryption(KeyInfo keyInfo, String plainText) throws GeneralSecurityException {
        RSAEncryptor enc = new RSAEncryptor(keyInfo);
        byte[] initVct = null;
        EncryptionOutputData outData = enc.encryptData(plainText, initVct);
        printResult(keyInfo, plainText, initVct, enc.getAESSessionKey(), outData);

        return outData;
    }

    /**
     * 処理の結果を出力します。
     * 
     * @param keyInfo RSA公開鍵情報
     * @param plainText 平文
     * @param initVctOrg 初期化ベクトル
     * @param aesKey AES鍵
     * @param outData 暗号化結果データ
     * @throws GeneralSecurityException 公開鍵の取得で例外がスローされた場合
     * @since 1.00
     */
    private void printResult(KeyInfo keyInfo, String plainText, byte[] initVctOrg, SecretKey aesKey,
            EncryptionOutputData outData) throws GeneralSecurityException {
        System.out.println(">>>> 入力情報 : ");
        System.out.println(keyInfo);
        System.out.println("Plain Text = " + plainText);
        String initVctOrgHex = (null == initVctOrg ? "null" : Utils.getHexString(initVctOrg));
        System.out.println("Initial vector (specified) = " + initVctOrgHex);

        byte[] cipherData = outData.getCipherText();
        byte[] initVct = outData.getInitialVector();
        byte[] encryptedKey = outData.getEncryptedKey();

        System.out.println(">>>> 出力結果 : ");
        System.out.println("Cipher Data = " + Utils.getHexString(cipherData));
        System.out.println("Initial vector (used) = " + Utils.getHexString(initVct));
        System.out.println("AES key = " + Utils.getHexString(aesKey.getEncoded()));
        PublicKey publicKey = keyInfo.getPublicKey();
        System.out.println("RSA public key = " + Utils.getHexString(publicKey.getEncoded()));
        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            byte[] modulus = rsaPublicKey.getModulus().toByteArray();
            System.out.println("RSA public key modulus = " + Utils.getHexString(modulus));
            System.out.println("RSA public key exponent = "
                    + Utils.getHexString(rsaPublicKey.getPublicExponent().toByteArray()));
            System.out.println("Length of RSA public key = " + modulus.length);
        }
        System.out.println("RSA-Encrypted AES Key = " + Utils.getHexString(encryptedKey));
        System.out.println("Length of encrypted AES key = " + encryptedKey.length);
    }

    /**
     * 暗号化されたデータが正しく復号されることを検証するための登場人物。アリスは自身のキーストアにRSA秘密鍵を保持する。
     * 
     * @version 1.00, 2017/08/31
     * @since 1.00
     */
    static class Alice {
        /**
         * キーストア・エントリーの別名
         */
        private final String alias = "alice";
        /**
         * キーストアのタイプ
         */
        private final String keyStoreType = "JCEKS";
        /**
         * キーストア・ファイルのパス
         */
        private final String keyStoreFilePath = "alice.jck";
        /**
         * キーストアのパスワード
         */
        private final String keyStorePassword = "alicepass";
        /**
         * 秘密鍵のパスワード
         */
        private final String keyPassword = "alicepass";

        /**
         * 暗号化結果データを復号し、結果を返します。
         * 
         * @param outData 暗号化結果データ
         * @return 復号されたバイト列
         * @throws GeneralSecurityException 復号処理で例外がスローされた場合
         * @since 1.00
         */
        public byte[] decrypt(EncryptionOutputData outData) throws GeneralSecurityException {
            KeyStoreKeyInfo keyInfo = new KeyStoreKeyInfo(alias, keyStoreType, keyStoreFilePath, keyStorePassword);
            // 暗号化されたAES鍵を復号する
            byte[] aesKey = decryptKey(keyInfo.getPrivateKey(keyPassword), outData.getEncryptedKey());
            // AES鍵を使用して暗号化データを復号する
            return decryptData(new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(outData.getInitialVector()),
                    outData.getCipherText());
        }

        /**
         * RSA秘密鍵を使用して暗号化されたAES鍵を復号します。
         * 
         * @param privateKey RSA秘密鍵
         * @param encryptedKey 暗号化されたAES鍵
         * @return 復号されたAES鍵
         * @throws GeneralSecurityException 復号処理で例外がスローされた場合
         * @since 1.00
         */
        private byte[] decryptKey(PrivateKey privateKey, byte[] encryptedKey) throws GeneralSecurityException {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encryptedKey);
        }

        /**
         * AES鍵を使用して暗号化されたデータを復号します。
         * 
         * @param aesKey AES鍵
         * @param iv 暗号化の際に使用した初期化ベクトル
         * @param data 暗号化されたデータ
         * @return 復号されたデータ
         * @throws GeneralSecurityException 復号処理で例外がスローされた場合
         * @since 1.00
         */
        private byte[] decryptData(SecretKey aesKey, AlgorithmParameterSpec iv, byte[] data)
                throws GeneralSecurityException {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
            // AES復号実施
            return cipher.doFinal(data);
        }
    }
}
