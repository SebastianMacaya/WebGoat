/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.mailbox;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import org.assertj.core.api.Assertions;
import org.jsoup.Jsoup;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.owasp.webgoat.webwolf.WebSecurityConfig;
import org.owasp.webgoat.webwolf.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(MailboxController.class)
@Import(WebSecurityConfig.class)
public class MailboxControllerTest {

  @Autowired private MockMvc mvc;
  @MockBean private MailboxRepository mailbox;

  @MockBean private ClientRegistrationRepository clientRegistrationRepository;
  @MockBean private UserService userService;
  @Autowired private ObjectMapper objectMapper;

  @JsonIgnoreProperties("time")
  public static class EmailMixIn {}

  @BeforeEach
  public void setup() {
    objectMapper.addMixIn(Email.class, EmailMixIn.class);
  }

  @Test
  public void sendingMailShouldStoreIt() throws Exception {
    Email email =
        Email.builder()
            .contents("This is a test mail")
            .recipient("test1234@webgoat.org")
            .sender("hacker@webgoat.org")
            .title("Click this mail")
            .time(LocalDateTime.now())
            .build();
    this.mvc
        .perform(
            post("/mail")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(email)))
        .andExpect(status().isCreated());
  }

  @Test
  @WithMockUser(username = "test1234")
  public void userShouldBeAbleToReadOwnEmail() throws Exception {
    Email email =
        Email.builder()
            .contents("This is a test mail")
            .recipient("test1234@webgoat.org")
            .sender("hacker@webgoat.org")
            .title("Click this mail")
            .time(LocalDateTime.now())
            .build();
    Mockito.when(mailbox.findByRecipientOrderByTimeDesc("test1234"))
        .thenReturn(Lists.newArrayList(email));

    this.mvc
        .perform(get("/mail"))
        .andExpect(status().isOk())
        .andExpect(view().name("mailbox"))
        .andExpect(content().string(containsString("Click this mail")))
        .andExpect(
            content()
                .string(
                    containsString(
                        DateTimeFormatter.ofPattern("h:mm a").format(email.getTimestamp()))));
  }

  @Test
  @WithMockUser(username = "tom")
  public void webwolfPostmarkKeepsAnchorButDropsScripts() throws Exception {
    String resetUrl =
        "http://127.0.0.1:8080/WebGoat/PasswordReset/reset/reset-password/"
            + "db680b68-a14a-465b-b861-2e3a6c70c0de";
    Email email =
        Email.builder()
            .contents(
                "<script>fetch('/WebWolf/landing/stolen')</script>"
                    + "<img src=x onerror=alert(1)>"
                    + "<a href='javascript:alert(1)' onclick='alert(1)'>bad link</a>"
                    + "<a href='"
                    + resetUrl
                    + "' target='_blank' onclick='alert(1)'>reset link</a>")
            .recipient("tom")
            .sender("password-reset@webgoat-cloud.net")
            .title("Your password reset link")
            .time(LocalDateTime.now())
            .build();
    Mockito.when(mailbox.findByRecipientOrderByTimeDesc("tom"))
        .thenReturn(Lists.newArrayList(email));

    var result = this.mvc.perform(get("/mail")).andExpect(status().isOk()).andReturn();
    String renderedMail =
        Jsoup.parse(result.getResponse().getContentAsString()).selectFirst(".contents pre").html();
    Assertions.assertThat(renderedMail)
        .contains("href=\"" + resetUrl + "\"", "reset link")
        .doesNotContain("<script", "onerror=", "onclick=", "javascript:");
  }

  @Test
  @WithMockUser(username = "test1234")
  public void safeResetMailKeepsOriginalLinkMarkup() throws Exception {
    String resetUrl =
        "http://127.0.0.1:8080/WebGoat/PasswordReset/reset/reset-password/"
            + "db680b68-a14a-465b-b861-2e3a6c70c0de";
    Email email =
        Email.builder()
            .contents("Use <a target='_blank' href='" + resetUrl + "'>link</a> to reset")
            .recipient("test1234")
            .sender("password-reset@webgoat-cloud.net")
            .title("Your password reset link")
            .time(LocalDateTime.now())
            .build();
    Mockito.when(mailbox.findByRecipientOrderByTimeDesc("test1234"))
        .thenReturn(Lists.newArrayList(email));

    this.mvc
        .perform(get("/mail"))
        .andExpect(status().isOk())
        .andExpect(content().string(containsString("href='" + resetUrl + "'")));
  }

  @Test
  @WithMockUser(username = "test1233")
  public void differentUserShouldNotBeAbleToReadOwnEmail() throws Exception {
    Email email =
        Email.builder()
            .contents("This is a test mail")
            .recipient("test1234@webgoat.org")
            .sender("hacker@webgoat.org")
            .title("Click this mail")
            .time(LocalDateTime.now())
            .build();
    Mockito.when(mailbox.findByRecipientOrderByTimeDesc("test1234"))
        .thenReturn(Lists.newArrayList(email));

    this.mvc
        .perform(get("/mail"))
        .andExpect(status().isOk())
        .andExpect(view().name("mailbox"))
        .andExpect(content().string(not(containsString("Click this mail"))));
  }
}
