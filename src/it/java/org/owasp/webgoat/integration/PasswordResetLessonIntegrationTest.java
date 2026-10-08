/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.integration;

import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import io.restassured.RestAssured;
import java.net.URI;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.springframework.http.HttpHeaders;

public class PasswordResetLessonIntegrationTest extends IntegrationTest {

  @BeforeEach
  public void init() {
    startLesson("PasswordReset");
  }

  @TestFactory
  Iterable<DynamicTest> passwordResetLesson() {
    return Arrays.asList(
        dynamicTest("assignment 6 - check email link", () -> sendEmailShouldBeAvailableInWebWolf()),
        dynamicTest(
            "assignment 6 - poisoned Tom request cannot reach attacker mailbox",
            () -> tomHostCannotLeakIntoWebWolf()),
        dynamicTest(
            "assignment 6 - another account's link cannot reset Tom",
            () -> anotherPersonsLinkCannotResetTom()),
        dynamicTest(
            "assignment 6 - a password change revokes older links",
            () -> olderLinksCannotResetAfterPasswordChange()),
        dynamicTest("assignment 2 - simple reset", () -> assignment2()),
        dynamicTest("assignment 4 - guess questions", () -> assignment4()),
        dynamicTest("assignment 5 - simple questions", () -> assignment5()));
  }

  public void assignment2() {
      checkAssignment(
              webGoatUrlConfig.url("PasswordReset/simple-mail/reset"),
        Map.of("emailReset", this.getUser() + "@webgoat.org"),
        false);
      checkAssignment(
              webGoatUrlConfig.url("PasswordReset/simple-mail"),
        Map.of(
            "email",
            this.getUser() + "@webgoat.org",
            "password",
            StringUtils.reverse(this.getUser())),
        true);
  }

  public void assignment4() {
      checkAssignment(
              webGoatUrlConfig.url("PasswordReset/questions"),
        Map.of("username", "tom", "securityQuestion", "purple"),
        true);
  }

  public void assignment5() {
      checkAssignment(
              webGoatUrlConfig.url("PasswordReset/SecurityQuestions"),
        Map.of("question", "What is your favorite animal?"),
        false);
      checkAssignment(
              webGoatUrlConfig.url("PasswordReset/SecurityQuestions"),
        Map.of("question", "What is your favorite color?"),
        true);
  }

  public void anotherPersonsLinkCannotResetTom() {
    cleanMailbox();
    clickForgotEmailLink(this.getUser() + "@webgoat.org");
    var link = getPasswordResetLinkFromMailbox();
    String newPassword = "P" + UUID.randomUUID().toString().substring(0, 7);
    Assertions.assertThat(changePassword(link, newPassword))
        .contains("Password changed successfully");
    checkAssignment(
        webGoatUrlConfig.url("PasswordReset/reset/login"),
        Map.of("email", "tom@webgoat-cloud.org", "password", newPassword),
        false);
  }

  public void olderLinksCannotResetAfterPasswordChange() {
    cleanMailbox();
    clickForgotEmailLink(this.getUser() + "@webgoat.org");
    String olderUrl = getPasswordResetUrlFromMailbox();
    String olderLink = URI.create(olderUrl).getPath().replaceFirst(".*/", "");

    cleanMailbox();
    clickForgotEmailLink(this.getUser() + "@webgoat.org");
    String newerUrl = getPasswordResetUrlFromMailbox();
    String newerLink = URI.create(newerUrl).getPath().replaceFirst(".*/", "");
    Assertions.assertThat(newerLink).isNotEqualTo(olderLink);

    String form =
        RestAssured.given()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .get(newerUrl)
            .then()
            .statusCode(200)
            .extract()
            .asString();
    Assertions.assertThat(form).contains("Reset your password", newerLink);

    String newPassword = "P" + UUID.randomUUID().toString().substring(0, 7);
    Assertions.assertThat(changePassword(newerLink, newPassword))
        .contains("Password changed successfully");
    Assertions.assertThat(
            RestAssured.given()
                .relaxedHTTPSValidation()
                .cookie("JSESSIONID", getWebGoatCookie())
                .get(newerUrl)
                .then()
                .statusCode(200)
                .extract()
                .asString())
        .contains("Password reset link is not valid");
    Assertions.assertThat(changePassword(olderLink, "Other123"))
        .contains("Password reset link is not valid");
  }

  public void sendEmailShouldBeAvailableInWebWolf() {
    clickForgotEmailLink(this.getUser() + "@webgoat.org");

    Assertions.assertThat(getLatestPasswordResetEmail())
        .contains("Hi, you requested a password reset link")
        .contains("/PasswordReset/reset/reset-password/")
        .doesNotContain("attacker.example");
  }

  public void tomHostCannotLeakIntoWebWolf() {
    cleanMailbox();
    int resetGetsBefore =
        StringUtils.countMatches(getWebWolfRequests(), "/PasswordReset/reset/reset-password/");
    Boolean completed =
        RestAssured.given()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .header(HttpHeaders.HOST, "127.0.0.1:" + webWolfUrlConfig.port())
            .formParam("email", "tom@webgoat-cloud.org")
            .post(webGoatUrlConfig.url("PasswordReset/ForgotPassword/create-password-reset-link"))
            .then()
            .statusCode(200)
            .extract()
            .path("lessonCompleted");
    Assertions.assertThat(completed).isFalse();
    Assertions.assertThat(getMailboxPage())
        .doesNotContain("/PasswordReset/reset/reset-password/");
    Assertions.assertThat(
            StringUtils.countMatches(getWebWolfRequests(), "/PasswordReset/reset/reset-password/"))
        .isEqualTo(resetGetsBefore);
  }

  private String changePassword(String link, String password) {
    return RestAssured.given()
        .when()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .formParams("resetLink", link, "password", password)
        .post(webGoatUrlConfig.url("PasswordReset/reset/change-password"))
        .then()
        .statusCode(200)
        .extract()
        .asString();
  }

  private String getLatestPasswordResetEmail() {
    var responseBody = getMailboxPage();
    Matcher message = Pattern.compile("(?s)<pre[^>]*>(.*?)</pre>").matcher(responseBody);
    Assertions.assertThat(message.find()).isTrue();
    return message.group(1);
  }

  private String getMailboxPage() {
    return RestAssured.given()
        .relaxedHTTPSValidation()
        .cookie("WEBWOLFSESSION", getWebWolfCookie())
        .get(webWolfUrlConfig.url("mail"))
        .then()
        .statusCode(200)
        .extract()
        .asString();
  }

  private String getWebWolfRequests() {
    return RestAssured.given()
        .relaxedHTTPSValidation()
        .cookie("WEBWOLFSESSION", getWebWolfCookie())
        .get(webWolfUrlConfig.url("requests"))
        .then()
        .statusCode(200)
        .extract()
        .asString();
  }

  private String getPasswordResetLinkFromMailbox() {
    Matcher token =
        Pattern.compile("/PasswordReset/reset/reset-password/([0-9a-f-]{36})")
            .matcher(getLatestPasswordResetEmail());
    Assertions.assertThat(token.find()).isTrue();
    return token.group(1);
  }

  private String getPasswordResetUrlFromMailbox() {
    Matcher link =
        Pattern.compile("href='(https?://[^']+/PasswordReset/reset/reset-password/[0-9a-f-]{36})'")
            .matcher(getLatestPasswordResetEmail());
    Assertions.assertThat(link.find()).isTrue();
    return link.group(1);
  }

  private void clickForgotEmailLink(String user) {
    RestAssured.given()
        .when()
        .header(HttpHeaders.HOST, "attacker.example")
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .formParams("email", user)
        .post(webGoatUrlConfig.url("PasswordReset/ForgotPassword/create-password-reset-link"))
        .then()
        .statusCode(200);
  }
}
