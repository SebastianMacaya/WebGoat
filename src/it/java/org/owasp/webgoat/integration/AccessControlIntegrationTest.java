/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.integration;

import static org.assertj.core.api.Assertions.assertThat;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import java.util.Map;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.lessons.missingac.DisplayUser;
import org.owasp.webgoat.lessons.missingac.MissingFunctionAC;
import org.owasp.webgoat.lessons.missingac.User;

class AccessControlIntegrationTest extends IntegrationTest {

  @Test
  void ordinaryUserCannotReachAdministrativeFunctions() {
    startLesson("MissingFunctionAC", true);

    String lessonHtml =
        RestAssured.given()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .get(webGoatUrlConfig.url("MissingFunctionAC.lesson.lesson"))
            .then()
            .statusCode(HttpStatus.SC_OK)
            .extract()
            .asString();
    assertThat(lessonHtml).doesNotContain("access-control/users-admin-fix");

    assertForbiddenGet("access-control/users");
    assertForbiddenJsonGet("access-control/users");
    assertForbiddenJsonGet("access-control/users-admin-fix");

    String selfGrant =
        """
        {"username":"%s","password":"password","admin":true}
        """
            .formatted(getUser());
    assertForbiddenJsonPost("access-control/users", selfGrant);
    assertForbiddenJsonPost("access-control/users-admin-fix", selfGrant);

    String simpleHash = "SVtOlaa+ER+w2eoIIVE5/77umvhcsh5V8UyDLUa1Itg=";
    String adminHash =
        new DisplayUser(
                new User("Jerry", "doesnotreallymatter", true),
                MissingFunctionAC.PASSWORD_SALT_ADMIN)
            .getUserHash();
    assertForbiddenForm(
        "access-control/hidden-menu", Map.of("hiddenMenu1", "Users", "hiddenMenu2", "Config"));
    assertForbiddenForm("access-control/user-hash", Map.of("userHash", simpleHash));
    assertForbiddenForm("access-control/user-hash-fix", Map.of("userHash", adminHash));
  }

  private void assertForbiddenGet(String path) {
    RestAssured.given()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .get(webGoatUrlConfig.url(path))
        .then()
        .statusCode(HttpStatus.SC_FORBIDDEN);
  }

  private void assertForbiddenJsonGet(String path) {
    RestAssured.given()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .contentType(ContentType.JSON)
        .get(webGoatUrlConfig.url(path))
        .then()
        .statusCode(HttpStatus.SC_FORBIDDEN);
  }

  private void assertForbiddenJsonPost(String path, String body) {
    RestAssured.given()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .contentType(ContentType.JSON)
        .body(body)
        .post(webGoatUrlConfig.url(path))
        .then()
        .statusCode(HttpStatus.SC_FORBIDDEN);
  }

  private void assertForbiddenForm(String path, Map<String, String> params) {
    RestAssured.given()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .formParams(params)
        .post(webGoatUrlConfig.url(path))
        .then()
        .statusCode(HttpStatus.SC_FORBIDDEN);
  }
}
