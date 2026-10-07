/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.integration;

import static org.junit.jupiter.api.Assertions.fail;

import io.restassured.RestAssured;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.lessons.cryptography.CryptoUtil;
import org.owasp.webgoat.lessons.cryptography.HashingAssignment;

public class CryptoIntegrationTest extends IntegrationTest {

  @Test
  public void runTests() {
    startLesson("Cryptography");

    checkAssignment2();
    checkAssignment3();

    // Assignment 4
    try {
      checkAssignment4();
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      fail();
    }

    try {
      checkAssignmentSigning();
    } catch (Exception e) {
      e.printStackTrace();
      fail();
    }

    checkAssignmentDefaults();

    // The signing exercise cannot be completed using a key disclosed by the verifier.
  }

  private void checkAssignment2() {

      String basicEncoding =
        RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .get(webGoatUrlConfig.url("crypto/encoding/basic"))
            .then()
            .extract()
            .asString();
    basicEncoding = basicEncoding.substring("Authorization: Basic ".length());
    String decodedString = new String(Base64.getDecoder().decode(basicEncoding.getBytes()));
    String answer_user = decodedString.split(":")[0];
    String answer_pwd = decodedString.split(":")[1];
    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("answer_user", answer_user);
    params.put("answer_pwd", answer_pwd);
      checkAssignment(webGoatUrlConfig.url("crypto/encoding/basic-auth"), params, true);
  }

  private void checkAssignment3() {
    String answer_1 = "databasepassword";
    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("answer_pwd1", answer_1);
      checkAssignment(webGoatUrlConfig.url("crypto/encoding/xor"), params, true);
  }

  private void checkAssignment4() throws NoSuchAlgorithmException {

      String md5Hash =
        RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .get(webGoatUrlConfig.url("crypto/hashing/md5"))
            .then()
            .extract()
            .asString();

      String sha256Hash =
        RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .get(webGoatUrlConfig.url("crypto/hashing/sha256"))
            .then()
            .extract()
            .asString();

    String answer_1 = "unknown";
    String answer_2 = "unknown";
    for (String secret : HashingAssignment.SECRETS) {
      if (md5Hash.equals(HashingAssignment.getHash(secret, "MD5"))) {
        answer_1 = secret;
      }
      if (sha256Hash.equals(HashingAssignment.getHash(secret, "SHA-256"))) {
        answer_2 = secret;
      }
    }

    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("answer_pwd1", answer_1);
    params.put("answer_pwd2", answer_2);
      checkAssignment(webGoatUrlConfig.url("crypto/hashing"), params, true);
  }

  private void checkAssignmentSigning()
      throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {

    RestAssured.given()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .get(webGoatUrlConfig.url("crypto/signing/getprivate"))
        .then()
        .statusCode(403);

      String publicPEM =
        RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .get(webGoatUrlConfig.url("crypto/signing/getpublic"))
            .then()
            .extract()
            .asString();
    byte[] encodedPublicKey =
        Base64.getMimeDecoder()
            .decode(
                publicPEM
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", ""));
    PublicKey publicKey =
        KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encodedPublicKey));
    String modulus =
        DatatypeConverter.printHexBinary(((RSAPublicKey) publicKey).getModulus().toByteArray());
    String signature = CryptoUtil.signMessage(modulus, CryptoUtil.generateKeyPair().getPrivate());
    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("modulus", modulus);
    params.put("signature", signature);
      checkAssignment(webGoatUrlConfig.url("crypto/signing/verify"), params, false);
  }

  private void checkAssignmentDefaults() {

    String text =
        new String(
            Base64.getDecoder()
                .decode(
                    "TGVhdmluZyBwYXNzd29yZHMgaW4gZG9ja2VyIGltYWdlcyBpcyBub3Qgc28gc2VjdXJl"
                        .getBytes(Charset.forName("UTF-8"))));

    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("secretText", text);
    params.put("secretFileName", "default_secret");
      checkAssignment(webGoatUrlConfig.url("crypto/secure/defaults"), params, true);
  }
}
