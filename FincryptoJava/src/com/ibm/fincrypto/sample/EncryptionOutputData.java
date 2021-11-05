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

/**
 * 暗号化実行結果を保持します。
 * 
 * @version 1.00, 2017/08/31
 * @since 1.00
 */
public class EncryptionOutputData {
    /**
     * 暗号化されたデータです。
     */
    private byte[] cipherText = null;

    /**
     * 初期化ベクトルです。
     */
    private byte[] initialVector = null;

    /**
     * 暗号化されたAES鍵です。
     */
    private byte[] encryptedKey = null;

    /**
     * 暗号化されたデータを返します。
     * 
     * @return 暗号化されたデータ
     * @since 1.00
     */
    public byte[] getCipherText() {
        return cipherText;
    }

    /**
     * 初期化ベクトルを返します。
     * 
     * @return 初期化ベクトル
     * @since 1.00
     */
    public byte[] getInitialVector() {
        return initialVector;
    }

    /**
     * RSA公開鍵により暗号化されたAES鍵を返します。
     * 
     * @return 暗号化されたAES鍵
     * @since 1.00
     */
    public byte[] getEncryptedKey() {
        return encryptedKey;
    }

    /**
     * 暗号化されたデータを設定します。
     * 
     * @param cipherText 暗号化されたデータ
     * @since 1.00
     */
    void setCipherText(byte[] cipherText) {
        this.cipherText = cipherText;
    }

    /**
     * 初期化ベクトルを設定します。
     * 
     * @param initialVector 初期化ベクトル
     * @since 1.00
     */
    void setInitialVector(byte[] initialVector) {
        this.initialVector = initialVector;
    }

    /**
     * 暗号化されたAES鍵を設定します。
     * 
     * @param encryptedKey 暗号化されたAES鍵
     * @since 1.00
     */
    void setEncryptedKey(byte[] encryptedKey) {
        this.encryptedKey = encryptedKey;
    }

}
