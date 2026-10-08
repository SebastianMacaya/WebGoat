/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.web.client.RestTemplate;

@TestPropertySource(
    properties = {
      "server.address=0.0.0.0",
      "WEBGOAT_PUBLIC_URL=http://webgoat:8080/WebGoat"
    })
class ResetLinkDockerUrlTest extends LessonTest {

  @Value("${webwolf.mail.url}")
  private String webWolfMailURL;

  @MockBean private RestTemplate restTemplate;

  @Test
  void webgoatPostmarkSurvivesTheDockerBoundary() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/ForgotPassword/create-password-reset-link")
                .param("email", "test@webgoat.org")
                .header(HttpHeaders.HOST, "attacker.example:9090"))
        .andExpect(status().isOk());

    ArgumentCaptor<PasswordResetEmail> mail = ArgumentCaptor.forClass(PasswordResetEmail.class);
    verify(restTemplate).postForEntity(eq(webWolfMailURL), mail.capture(), eq(Object.class));
    Assertions.assertThat(mail.getValue().getContents())
        .contains("href='http://webgoat:8080/WebGoat/PasswordReset/reset/reset-password/")
        .doesNotContain("0.0.0.0")
        .doesNotContain("attacker.example");
  }
}
