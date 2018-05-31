/*
 * Copyright (C) 2015 Richard "Shred" KÃ¶rber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package com.kantenkugel.acmeclient;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;

class Entities {
    private static final Logger LOG = LoggerFactory.getLogger(Entities.class);

    // File name of the User Key Pair
    private static final File USER_KEY_FILE = new File("user.key");

    // File name of the Domain Key Pair
    private static final File DOMAIN_KEY_FILE = new File("domain.key");

    // RSA key size of generated key pairs
    private static final int KEY_SIZE = 4096;

    static KeyPair loadOrCreateAccountKeyPair() throws IOException {
        KeyPair kp = loadAccountKeyPair();
        if(kp != null)
            return kp;

        // If there is none, create a new key pair and save it
        KeyPair userKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
        try (FileWriter fw = new FileWriter(USER_KEY_FILE)) {
            KeyPairUtils.writeKeyPair(userKeyPair, fw);
        }
        return userKeyPair;
    }

    static KeyPair loadAccountKeyPair() throws IOException {
        if (USER_KEY_FILE.exists()) {
            // If there is a key file, read it
            try (FileReader fr = new FileReader(USER_KEY_FILE)) {
                return KeyPairUtils.readKeyPair(fr);
            }
        } else {
            return null;
        }
    }

    static KeyPair loadOrCreateDomainKeyPair() throws IOException {
        KeyPair kp = loadDomainKeyPair();
        if(kp != null)
            return kp;

        KeyPair domainKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
        try (FileWriter fw = new FileWriter(DOMAIN_KEY_FILE)) {
            KeyPairUtils.writeKeyPair(domainKeyPair, fw);
        }
        return domainKeyPair;
    }

    static KeyPair loadDomainKeyPair() throws IOException {
        if (DOMAIN_KEY_FILE.exists()) {
            try (FileReader fr = new FileReader(DOMAIN_KEY_FILE)) {
                return KeyPairUtils.readKeyPair(fr);
            }
        } else {
            return null;
        }
    }

    static Account findOrRegisterAccount(Session session, KeyPair accountKey, boolean skipToS) throws AcmeException {
        // Ask the user to accept the TOS, if server provides us with a link.
        URI tos = session.getMetadata().getTermsOfService();
        if (tos != null && !skipToS) {
            Utils.acceptAgreement(tos);
        }

        Account account = new AccountBuilder()
                .agreeToTermsOfService()
                .useKeyPair(accountKey)
                .create(session);
        LOG.debug("Registered a new user, URL: " + account.getLocation());

        return account;
    }
}
