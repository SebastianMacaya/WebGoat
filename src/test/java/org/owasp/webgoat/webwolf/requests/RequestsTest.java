/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.requests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.web.exchanges.HttpExchange;
import org.springframework.security.core.Authentication;

class RequestsTest {

  @Test
  void landingVerificationTracesAreVisibleOnlyToTheirOwner() throws Exception {
    var traceRepository = mock(WebWolfTraceRepository.class);
    var objectMapper = mock(ObjectMapper.class);
    when(objectMapper.writeValueAsString(any(HttpExchange.class))).thenReturn("{}");
    when(traceRepository.findAll())
        .thenReturn(
            List.of(
                landingTrace("uniqueCode=secret1&username=alice"),
                landingTrace("uniqueCode=secret2&username=bob"),
                landingTrace("uniqueCode=secret3&username=bob&note=alice")));
    var authentication = mock(Authentication.class);
    when(authentication.getName()).thenReturn("alice");

    var requests = new Requests(traceRepository, objectMapper);
    var traces = (List<?>) requests.get(authentication).getModel().get("traces");

    assertEquals(1, traces.size());
  }

  private static HttpExchange landingTrace(String query) {
    var request =
        new HttpExchange.Request(
            URI.create("http://localhost/landing?" + query), "GET", "127.0.0.1", Map.of());
    return new HttpExchange(Instant.EPOCH, request, null, null, null, Duration.ZERO);
  }
}
