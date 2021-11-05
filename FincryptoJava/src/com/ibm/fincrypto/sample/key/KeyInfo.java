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

import java.security.GeneralSecurityException;
import java.security.PublicKey;

/**
 * RSA公開鍵情報のインターフェースです。
 * 
 * @version 1.00, 2017/08/31
 * @since 1.00
 */
public interface KeyInfo {
    /**
     * RSA公開鍵を取得します。
     * 
     * @return RSA公開鍵
     * @throws GeneralSecurityException 公開鍵の取得に際して例外がスローされた場合
     * @since 1.00
     */
    public PublicKey getPublicKey() throws GeneralSecurityException;
}
