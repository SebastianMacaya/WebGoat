/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import javax.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class SigningAssignmentTest extends LessonTest {

  @Test
  void privateKeyIsNotAvailableAndUnrelatedSignatureCannotVerify() throws Exception {
    MockHttpSession session = new MockHttpSession();

    mockMvc
        .perform(MockMvcRequestBuilders.get("/crypto/signing/getprivate").session(session))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(MockMvcRequestBuilders.get("/crypto/signing/getpublic").session(session))
        .andExpect(status().isOk())
        .andExpect(content().string(containsString("-----BEGIN PUBLIC KEY-----")))
        .andExpect(content().string(not(containsString("PRIVATE KEY"))));

    KeyPair serverKeyPair = (KeyPair) session.getAttribute("keyPair");
    String modulus =
        DatatypeConverter.printHexBinary(
            ((RSAPublicKey) serverKeyPair.getPublic()).getModulus().toByteArray());
    String forgedSignature =
        CryptoUtil.signMessage(modulus, CryptoUtil.generateKeyPair().getPrivate());

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/crypto/signing/verify")
                .session(session)
                .param("modulus", modulus)
                .param("signature", forgedSignature))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false));

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/crypto/signing/verify")
                .session(session)
                .param("modulus", modulus)
                .param("signature", CryptoUtil.signMessage(modulus, serverKeyPair.getPrivate())))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(true));
  }

  @Test
  void verificationWithoutAnIssuedPublicKeyFailsSafely() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/crypto/signing/verify")
                .param("modulus", "00")
                .param("signature", "AA=="))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false));
  }
}
