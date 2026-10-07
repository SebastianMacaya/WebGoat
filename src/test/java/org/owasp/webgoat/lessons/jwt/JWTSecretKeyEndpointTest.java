/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@WithWebGoatUser
public class JWTSecretKeyEndpointTest extends LessonTest {

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  private Claims createClaims(String username) {
    Claims claims = Jwts.claims();
    claims.setExpiration(Date.from(Instant.now().plusSeconds(60)));
    claims.setIssuedAt(Date.from(Instant.now()));
    claims.setIssuer("WebGoat Token Builder");
    claims.setAudience("webgoat.org");
    claims.setSubject("tom@webgoat.org");
    claims.put("username", username);
    claims.put("Email", "tom@webgoat.org");
    claims.put("Role", new String[] {"Manager"});
    return claims;
  }

  private String signingKey() {
    return (String) ReflectionTestUtils.getField(JWTSecretKeyEndpoint.class, "JWT_SECRET");
  }

  @Test
  void signingKeyHasAtLeast512Bits() {
    assertTrue(Base64.getDecoder().decode(signingKey()).length >= 64);
  }

  @Test
  void validHs256SignatureCanStillBeVerified() throws Exception {
    String token =
        Jwts.builder()
            .setClaims(createClaims("WebGoat"))
            .signWith(SignatureAlgorithm.HS256, signingKey())
            .compact();

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/secret").param("token", token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  @Test
  void validHs512SignatureCanStillBeVerified() throws Exception {
    String token =
        Jwts.builder()
            .setClaims(createClaims("WebGoat"))
            .signWith(SignatureAlgorithm.HS512, signingKey())
            .compact();

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/secret").param("token", token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  @Test
  void issuedTokenDoesNotGrantAnotherUsersIdentity() throws Exception {
    String token =
        mockMvc
            .perform(MockMvcRequestBuilders.get("/JWT/secret/gettoken"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/secret").param("token", token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  void oldDictionarySecretCannotForgeWebGoatIdentity() throws Exception {
    String token =
        Jwts.builder()
            .setClaims(createClaims("WebGoat"))
            .signWith(SignatureAlgorithm.HS256, TextCodec.BASE64.encode("victory"))
            .compact();

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/secret").param("token", token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }

  @Test
  void unsignedTokenCannotForgeWebGoatIdentity() throws Exception {
    String token = Jwts.builder().setClaims(createClaims("WebGoat")).compact();

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/secret").param("token", token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}
