/*
 * Copyright (C) 2015 Richard "Shred" KÃ¶rber
 *   http://acme4j.shredzone.org
 *
 * Copyright (C) 2018 Michael "Kantenkugel" Ritter
 *   For modified parts of the example code
 *   (splitting into loadOrCreateX/loadX)
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

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;

import static com.kantenkugel.acmeclient.AcmeClient.LOG;

class Entities {
    // File name of the User Key Pair
    private static final File USER_KEY_FILE = new File("caAccount.key");

    // RSA key size of generated key pairs
    private static final int KEY_SIZE = 2048;

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
        LOG.info("Getting Account KeyPair");
        if (USER_KEY_FILE.exists()) {
            // If there is a key file, read it
            try (FileReader fr = new FileReader(USER_KEY_FILE)) {
                return KeyPairUtils.readKeyPair(fr);
            }
        } else {
            return null;
        }
    }

    static KeyPair loadOrCreateDomainKeyPair(File keyFile) throws IOException {
        KeyPair kp = loadDomainKeyPair(keyFile);
        if(kp != null)
            return kp;

        KeyPair domainKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
        try (FileWriter fw = new FileWriter(keyFile)) {
            KeyPairUtils.writeKeyPair(domainKeyPair, fw);
        }
        return domainKeyPair;
    }

    static KeyPair loadDomainKeyPair(File keyFile) throws IOException {
        LOG.info("Getting Domain KeyPair");
        if (keyFile.exists()) {
            try (FileReader fr = new FileReader(keyFile)) {
                return KeyPairUtils.readKeyPair(fr);
            }
        } else {
            return null;
        }
    }

    static Account findOrRegisterAccount(Session session, KeyPair accountKey, boolean skipToS) throws AcmeException {
        // Ask the user to accept the TOS, if server provides us with a link.
        LOG.info("Registering / Fetching account...");
        URI tos = session.getMetadata().getTermsOfService();
        if (tos != null && !skipToS) {
            if(!Utils.userConfirmation("Do you accept the Terms of Service?\n\n" + tos)) {
                throw new AcmeException("User didn't accept ToS");
            }
        }

        Account account = new AccountBuilder()
                .agreeToTermsOfService()
                .useKeyPair(accountKey)
                .create(session);
        LOG.debug("Registered a new user, URL: " + account.getLocation());

        return account;
    }
}
