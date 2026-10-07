/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.integration;

import static org.junit.jupiter.api.Assertions.assertTrue;

import io.restassured.RestAssured;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

public class WebWolfIntegrationTest extends IntegrationTest {

  @Test
  public void runTests() {
    startLesson("WebWolfIntroduction");

    // Assignment 3
    Map<String, Object> params = new HashMap<>();
    params.put("email", this.getUser() + "@webgoat.org");
      checkAssignment(webGoatUrlConfig.url("WebWolf/mail/send"), params, false);

    String responseBody =
        RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("WEBWOLFSESSION", getWebWolfCookie())
            .get(webWolfUrlConfig.url("mail"))
            .then()
            .extract()
            .response()
            .getBody()
            .asString();

    String uniqueCode =
        extractCode(responseBody.replace("%20", " "), "your unique code is: ([A-Za-z0-9_-]+)");
    params.clear();
    params.put("uniqueCode", uniqueCode);
      checkAssignment(webGoatUrlConfig.url("WebWolf/mail"), params, true);

    // Assignment 4
    String landingPage =
        RestAssured.given()
        .when()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .queryParams(params)
        .get(webGoatUrlConfig.url("WebWolf/landing/password-reset"))
        .then()
        .statusCode(200)
        .extract()
        .response()
        .getBody()
        .asString();
    String landingCode =
        extractCode(landingPage, "name=\"uniqueCode\"[^>]*value=\"([A-Za-z0-9_-]+)\"");
    params.put("uniqueCode", landingCode);
    params.put("username", getUser());
    RestAssured.given()
        .when()
        .relaxedHTTPSValidation()
        .cookie("WEBWOLFSESSION", getWebWolfCookie())
        .queryParams(params)
        .get(webWolfUrlConfig.url("landing"))
        .then()
        .statusCode(200);
    responseBody =
        RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("WEBWOLFSESSION", getWebWolfCookie())
            .get(webWolfUrlConfig.url("requests"))
            .then()
            .extract()
            .response()
            .getBody()
            .asString();
    assertTrue(responseBody.contains(landingCode));
    params.clear();
    params.put("uniqueCode", landingCode);
      checkAssignment(webGoatUrlConfig.url("WebWolf/landing"), params, true);

    checkResults("WebWolfIntroduction");
  }

  private static String extractCode(String response, String pattern) {
    var matcher = Pattern.compile(pattern).matcher(response);
    assertTrue(matcher.find(), "Verification code not found in response");
    return matcher.group(1);
  }
}
