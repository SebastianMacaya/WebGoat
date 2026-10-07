/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.integration;

import static org.assertj.core.api.Assertions.assertThat;

import io.restassured.RestAssured;
import java.io.IOException;
import org.apache.http.HttpStatus;
import org.dummy.insecure.framework.VulnerableTaskHolder;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.lessons.deserialization.SerializationHelper;

public class DeserializationIntegrationTest extends IntegrationTest {

  @Test
  public void runTests() throws IOException {
    startLesson("InsecureDeserialization");

    Boolean lessonCompleted =
        RestAssured.given()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .formParam(
                "token",
                SerializationHelper.toString(new VulnerableTaskHolder("wait", "sleep 5")))
            .post(webGoatUrlConfig.url("InsecureDeserialization/task"))
            .then()
            .statusCode(HttpStatus.SC_OK)
            .extract()
            .path("lessonCompleted");
    assertThat(lessonCompleted).isFalse();
  }
}
