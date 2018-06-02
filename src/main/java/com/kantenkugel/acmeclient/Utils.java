/*
 * Copyright (C) 2015 Richard "Shred" KÃ¶rber
 *   http://acme4j.shredzone.org
 *
 * Copyright (C) 2018 Michael "Kantenkugel" Ritter
 *   For modified parts of the example code
 *   (http challange file creation, user confirmation code)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

package com.kantenkugel.acmeclient;

import com.kantenkugel.acmeclient.config.SiteConfig;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;

import static com.kantenkugel.acmeclient.AcmeClient.LOG;

class Utils {
    private static final String CHALLANGE_DIR = "./.well-known/acme-challenge/";

    /**
     * Authorize a domain. It will be associated with your account, so you will be able to
     * retrieve a signed certificate for the domain later.
     *
     * @param auth
     *            {@link Authorization} to perform
     */
    static void authorize(Authorization auth, SiteConfig config) throws AcmeException {
        LOG.info("Authorization for domain " + auth.getDomain());

        // The authorization is already valid. No need to process a challenge.
        if (auth.getStatus() == Status.VALID) {
            return;
        }

        // Find a single http-01 challenge
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);
        if (challenge == null) {
            throw new AcmeException("Found no " + Http01Challenge.TYPE + " challenge, don't know what to do...");
        }

        // If the challenge is already verified, there's no need to execute it again.
        if (challenge.getStatus() == Status.VALID) {
            return;
        }

        LOG.info("Creating challenge files...");

        File challengeDir = new File(config.getStaticsDir(), CHALLANGE_DIR);
        if(!challengeDir.exists() && !challengeDir.mkdirs())
            throw new AcmeException("Could not create challenge directory " + challengeDir.getAbsolutePath());

        File challengeFile = new File(challengeDir, challenge.getToken());

        try(FileWriter fw = new FileWriter(challengeFile)) {
            fw.write(challenge.getAuthorization());
        } catch(IOException ex) {
            throw new AcmeException("Could not create challenge token file", ex);
        }

        // Now trigger the challenge.
        challenge.trigger();

        LOG.info("Waiting for challenge confirmation");

        // Poll for the challenge to complete.
        try {
            int attempts = 10;
            while (challenge.getStatus() != Status.VALID && attempts-- > 0) {
                // Did the authorization fail?
                if (challenge.getStatus() == Status.INVALID) {
                    throw new AcmeException("Challenge failed... Giving up.");
                }

                // Wait for a few seconds
                Thread.sleep(3000L);

                // Then update the status
                challenge.update();
            }
        } catch (InterruptedException ex) {
            LOG.error("interrupted", ex);
            Thread.currentThread().interrupt();
        }

        LOG.info("Cleaning up challenge files");
        challengeFile.delete();
        challengeDir.delete();
        challengeDir.getParentFile().delete();

        // All reattempts are used up and there is still no valid authorization?
        if (challenge.getStatus() != Status.VALID) {
            throw new AcmeException("Failed to pass the challenge for domain "
                    + auth.getDomain() + ", ... Giving up.");
        }
    }

    private static final Scanner sc = new Scanner(System.in);

    static boolean userConfirmation(String text) throws AcmeException {
        LOG.info(text + " [y/N]");
        return sc.nextLine().equalsIgnoreCase("y");
    }
}
