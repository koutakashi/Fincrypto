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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

/**
 * キーストアに格納されたRSA公開鍵/RSA秘密鍵を保持するクラスです。
 * 
 * @version 1.00, 2017/08/31
 * @since 1.00
 */
public class KeyStoreKeyInfo implements KeyInfo {

    /**
     * キーストア・エントリーの別名
     */
    private final String alias;
    /**
     * キーストアのタイプ
     */
    private final String keyStoreType;
    /**
     * キーストア・ファイルのパス
     */
    private final String keyStoreFile;
    /**
     * キーストア・ファイルのパスワード
     */
    private final String keyStorePass;
    /**
     * RSA公開鍵
     */
    private PublicKey publicKey;
    /**
     * RSA秘密鍵
     */
    private PrivateKey privateKey;

    /**
     * コンストラクタ。
     * 
     * @param alias キーストア・エントリーの別名
     * @param keyStoreType キーストアのタイプ
     * @param keyStoreFilePath キーストア・ファイルのパス
     * @param keyStorePassword キーストア・ファイルのパスワード
     * @since 1.00
     */
    public KeyStoreKeyInfo(String alias, String keyStoreType, String keyStoreFilePath, String keyStorePassword) {
        this.alias = alias;
        this.keyStoreType = keyStoreType;
        this.keyStoreFile = keyStoreFilePath;
        this.keyStorePass = keyStorePassword;
    }

    /**
     * キーストアから別名として登録されたRSA公開鍵を取得します。
     * 
     * @return RSA公開鍵
     * @throws GeneralSecurityException キーストアの処理もしくは公開鍵の処理で例外がスローされた場合
     * @since 1.00
     */
    @Override
    public PublicKey getPublicKey() throws GeneralSecurityException {
        if (publicKey == null) {
            KeyStore ks = KeyStore.getInstance(keyStoreType);
            try (InputStream is = new FileInputStream(keyStoreFile)){
            	ks.load(is, keyStorePass.toCharArray());
            } catch (IOException e) {
                throw new GeneralSecurityException("cannot handle keystore file correctly", e);
            }
            // 証明書からRSA公開鍵を取得する
            Certificate certificate = ks.getCertificate(alias);
            publicKey = certificate.getPublicKey();
        }
        return publicKey;
    }

    /**
     * キーストアから別名として登録されたRSA秘密鍵を取得します。
     * 
     * @param keyPassword 秘密鍵を保護するパスワード
     * @return RSA秘密鍵
     * @throws GeneralSecurityException キーストアの処理もしくは秘密鍵の処理で例外がスローされた場合
     * @since 1.00
     */
    public PrivateKey getPrivateKey(String keyPassword) throws GeneralSecurityException {
        if (privateKey == null) {
            KeyStore ks = KeyStore.getInstance(keyStoreType);
            try (InputStream is = new FileInputStream(keyStoreFile)){
                ks.load(is, keyStorePass.toCharArray());
            } catch (IOException e) {
                throw new GeneralSecurityException("cannot handle keystore file correctly.", e);
            }
            // パスワードを指定して秘密鍵を取得する
            Key key = ks.getKey(alias, keyPassword.toCharArray());
            if (key instanceof PrivateKey) {
                privateKey = (PrivateKey) key;
            } else {
                throw new GeneralSecurityException("cannot get the private key.");
            }
        }
        return privateKey;
    }

    /**
     * このインスタンスの文字列表現を返します。文字列表現には以下が含まれます。
     * <ul>
     * <li>キーストア・エントリーの別名
     * <li>キーストアのタイプ
     * <li>キーストア・ファイルのパス
     * <li>キーストア・ファイルのパスワード
     * </ul>
     * 
     * @return 文字列表現
     * @since 1.00
     */
    @Override
    public String toString() {
        final String nl = System.lineSeparator();
        StringBuilder sb = new StringBuilder();
        sb.append("alias = ").append(alias).append(nl);
        sb.append("keyStoreType = ").append(keyStoreType).append(nl);
        sb.append("keyStoreFile = ").append(keyStoreFile).append(nl);
        sb.append("keyStorePass = ").append(keyStorePass);
        return sb.toString();
    }

}
