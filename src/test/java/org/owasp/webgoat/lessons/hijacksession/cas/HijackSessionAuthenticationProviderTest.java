/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.hijacksession.cas;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.owasp.webgoat.lessons.hijacksession.cas.Authentication.AuthenticationBuilder;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

class HijackSessionAuthenticationProviderTest {

  HijackSessionAuthenticationProvider provider = new HijackSessionAuthenticationProvider();

  @ParameterizedTest
  @DisplayName("Provider authentication test")
  @MethodSource("authenticationForCookieValues")
  void testProviderAuthenticationGeneratesCookie(Authentication authentication) {
    Authentication auth = provider.authenticate(authentication);
    assertThat(auth.getId(), not(StringUtils.isEmpty(auth.getId())));
  }

  @Test
  void testAuthenticated() {
    String id = "anyId";
    provider.addSession(id);

    Authentication auth = provider.authenticate(Authentication.builder().id(id).build());

    assertThat(auth.getId(), is(id));
    assertThat(auth.isAuthenticated(), is(true));

    auth = provider.authenticate(Authentication.builder().id("otherId").build());

    assertThat(auth.getId(), is("otherId"));
    assertThat(auth.isAuthenticated(), is(false));
  }

  @Test
  void generatedIdsUseIndependentRandomTokens() {
    Set<String> ids = new HashSet<>();
    for (int i = 0; i < 200; i++) {
      String sessionId = HijackSessionAuthenticationProvider.AUTHENTICATION_SUPPLIER.get().getId();
      assertThat(sessionId.matches("[0-9]{1,19}-[0-9]{1,19}-[0-9a-f]{32}"), is(true));
      String[] parts = sessionId.split("-");
      Long.parseLong(parts[0]);
      Long.parseLong(parts[1]);
      ids.add(sessionId);
    }
    assertThat(ids.size(), is(200));
  }

  @Test
  void exactRandomSuffixIsRequiredForAuthentication() {
    String issuedId = HijackSessionAuthenticationProvider.AUTHENTICATION_SUPPLIER.get().getId();
    provider.addSession(issuedId);

    Authentication actual = provider.authenticate(Authentication.builder().id(issuedId).build());
    assertThat(actual.isAuthenticated(), is(true));

    char last = issuedId.charAt(issuedId.length() - 1);
    String guessedId = issuedId.substring(0, issuedId.length() - 1) + (last == '0' ? '1' : '0');
    Authentication guessed = provider.authenticate(Authentication.builder().id(guessedId).build());
    assertThat(guessed.isAuthenticated(), is(false));
  }

  @Test
  void failedLoginsDoNotAuthenticateClientWhileAuthorizedSessionsRemainAvailable() {
    for (int i = 0; i < 200; i++) {
      Authentication auth =
          provider.authenticate(Authentication.builder().name("guest").credentials("wrong").build());
      assertThat(auth.isAuthenticated(), is(false));
    }
    assertThat(provider.getSessionsSize() > 0, is(true));
  }

  @Test
  void testAuthenticationToString() {
    AuthenticationBuilder authBuilder =
        Authentication.builder()
            .name("expectedName")
            .credentials("expectedCredentials")
            .id("expectedId");

    Authentication auth = authBuilder.build();

    String expected =
        "Authentication.AuthenticationBuilder("
            + "name="
            + auth.getName()
            + ", credentials="
            + auth.getCredentials()
            + ", id="
            + auth.getId()
            + ")";

    assertThat(authBuilder.toString(), is(expected));

    expected =
        "Authentication(authenticated="
            + auth.isAuthenticated()
            + ", name="
            + auth.getName()
            + ", credentials="
            + auth.getCredentials()
            + ", id="
            + auth.getId()
            + ")";

    assertThat(auth.toString(), is(expected));
  }

  @Test
  void testMaxSessions() {
    for (int i = 0; i <= HijackSessionAuthenticationProvider.MAX_SESSIONS + 1; i++) {
      provider.addSession(null);
    }

    assertThat(provider.getSessionsSize(), is(HijackSessionAuthenticationProvider.MAX_SESSIONS));
  }

  private static Stream<Arguments> authenticationForCookieValues() {
    return Stream.of(
        Arguments.of((Object) null),
        Arguments.of(Authentication.builder().name("any").credentials("any").build()),
        Arguments.of(Authentication.builder().id("any").build()));
  }
}
