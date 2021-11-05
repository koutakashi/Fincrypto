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
package com.ibm.fincrypto.sample.key;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * PKCS#8 DER形式のRSA公開鍵を保持するクラスです。
 * 
 * @version 1.00, 2017/08/31
 * @since 1.00
 */
public class PKCS8KeyInfo implements KeyInfo {

    /**
     * キー・ファイルのパス
     */
    private final String keyFilename;
    /**
     * PKCS#8 DER形式のRSA公開鍵のバイト列
     */
    private final byte[] bytes;
    /**
     * RSA公開鍵
     */
    private PublicKey publicKey;

    /**
     * キー・ファイルを引数に取るコンストラクタ。
     * 
     * @param keyFilename キー・ファイルのパス
     * @throws GeneralSecurityException キー・ファイルの入力処理で例外がスローされた場合
     */
    public PKCS8KeyInfo(String keyFilename) throws GeneralSecurityException {
        this.keyFilename = keyFilename;
        try {
            this.bytes = Files.readAllBytes(new File(keyFilename).toPath());
        } catch (IOException e) {
            throw new GeneralSecurityException("cannot read the key file.", e);
        }
    }

    /**
     * バイト列を引数に取るコンストラクタ。
     * 
     * @param bytes PKCS#8 DER形式のバイト列
     */
    public PKCS8KeyInfo(byte[] bytes) {
        this.keyFilename = null;
        this.bytes = bytes;
    }

    /**
     * PKCS#8 DER形式のキー・ファイルからRSA公開鍵を取得します。
     * 
     * @return RSA公開鍵
     * @throws GeneralSecurityException 公開鍵の処理で例外がスローされた場合
     */
    @Override
    public PublicKey getPublicKey() throws GeneralSecurityException {
        if (publicKey == null) {
            KeySpec keySpec = new X509EncodedKeySpec(bytes);
            // KeySpecからRSA公開鍵を復元する
            KeyFactory factory = KeyFactory.getInstance("RSA");
            publicKey = factory.generatePublic(keySpec);
        }
        return publicKey;
    }

    /**
     * このインスタンスの文字列表現を返します。文字列表現には以下が含まれます。
     * <ul>
     * <li>キー・ファイルのパス
     * </ul>
     * 
     * @return 文字列表現
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("input source = ");
        if (keyFilename != null) {
            sb.append("file(" + keyFilename + ")");
        } else {
            sb.append("byte array input");
        }
        return sb.toString();
    }

}
