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

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;

/**
 * modulusとpublic exponentのペアで表されたRSA公開鍵を保持するクラスです。
 * 
 * @version 1.00, 2017/08/31
 * @since 1.00
 */
public class PairValueKeyInfo implements KeyInfo {
    /**
     * RSA公開鍵のModulus
     */
    private final BigInteger modulus;
    /**
     * RSA公開鍵のPublic exponent
     */
    private final BigInteger publicExponent;
    /**
     * RSA公開鍵
     */
    private PublicKey publicKey;

    /**
     * 16進数文字列表現を引数に取るコンストラクタ。
     * 
     * @param hexModules 16進数文字列表現文字列のModulus
     * @param hexPublicExponent 16進数文字列表現のPublic exponent
     */
    public PairValueKeyInfo(String hexModules, String hexPublicExponent) {
        modulus = new BigInteger(hexModules, 16);
        publicExponent = new BigInteger(hexPublicExponent, 16);
    }

    /**
     * <code>BigInteger</code>を引数に取るコンストラクタ。
     * 
     * @param modulus RSA公開鍵のmodulus
     * @param publicExponent RSA公開鍵のpublic exponent
     */
    public PairValueKeyInfo(BigInteger modulus, BigInteger publicExponent) {
        this.modulus = modulus;
        this.publicExponent = publicExponent;
    }

    /**
     * バイト列を引数に取るコンストラクタ。
     * 
     * @param modulus RSA公開鍵のmodulusのバイト列
     * @param publicExponent RSA公開鍵のpublic exponentのバイト列
     */
    public PairValueKeyInfo(byte[] modulus, byte[] publicExponent) {
        // BigIntegerのコンストラクタはバイト列を2の補数表現として解釈するので、先頭バイトに0を付与して正の整数にする
        byte[] modulus2 = new byte[modulus.length + 1];
        byte[] publicExponent2 = new byte[publicExponent.length + 1];
        modulus2[0] = 0;
        publicExponent2[0] = 0;
        System.arraycopy(modulus, 0, modulus2, 1, modulus.length);
        System.arraycopy(publicExponent, 0, publicExponent2, 1, publicExponent.length);

        this.modulus = new BigInteger(modulus2);
        this.publicExponent = new BigInteger(publicExponent2);
    }

    /**
     * ModulusとPublic exponentの2つの値を元にRSA公開鍵の情報を取得します。
     * 
     * @return 公開鍵
     * @throws GeneralSecurityException 公開鍵の処理で例外がスローされた場合
     */
    @Override
    public PublicKey getPublicKey() throws GeneralSecurityException {
        if (publicKey == null) {
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);

            // KeySpecから、公開RSAキーを復元する.
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(publicKeySpec);
        }
        return publicKey;
    }

    /**
     * このインスタンスの文字列表現を返します。文字列表現には以下が含まれます。
     * <ul>
     * <li>16進数文字列表現のModulus
     * <li>16進数文字列表現のPublic exponent
     * <li>Modulusの値
     * <li>Public exponentの値
     * </ul>
     * 
     * @return 文字列表現
     */
    @Override
    public String toString() {
        final String nl = System.lineSeparator();
        StringBuilder sb = new StringBuilder();
        sb.append("hexModules = ").append(modulus.toString(16)).append(nl);
        sb.append("hexPublicExponent = ").append(publicExponent.toString(16)).append(nl);
        sb.append("Modulus = ").append(modulus).append(nl);
        sb.append("Public exponent = ").append(publicExponent);
        return sb.toString();
    }
}
