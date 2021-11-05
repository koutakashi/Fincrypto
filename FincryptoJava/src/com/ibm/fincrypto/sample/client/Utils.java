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

/**
 * バイト列を16進数文字列としてダンプ出力するためのユーティリティ・クラスです。
 * 
 * @version 1.00, 2017/08/31
 * @since 1.00
 */
public class Utils {
    /**
     * 0から15までの数値に対応する文字コードの配列
     */
    private static final char[] hexCode = "0123456789ABCDEF".toCharArray();

    /**
     * 引数に与えられたバイト列の16進数文字列表現を取得します。
     * 
     * @param data バイト列
     * @return バイト列の16進数文字列表現
     * @since 1.00
     */
    public static String getHexString(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(hexCode[(b >> 4) & 0xF]);
            sb.append(hexCode[b & 0xF]);
        }
        return sb.toString();
    }
}
