/*
 * Copyright (C) 2015 Richard "Shred" KÃ¶rber
 *   For the most part of #requestCert(...)
 *   http://acme4j.shredzone.org
 *
 * Copyright (C) 2018 Michael "Kantenkugel" Ritter
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

package com.kantenkugel.acmeclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.kantenkugel.acmeclient.args.ArgParser;
import com.kantenkugel.acmeclient.args.Args;
import com.kantenkugel.acmeclient.config.Config;
import com.kantenkugel.acmeclient.config.SiteConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Security;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class AcmeClient {

    static final Logger LOG = LoggerFactory.getLogger(AcmeClient.class);

    private static final String ACME_ADDRESS = "acme://letsencrypt.org"; // acme://letsencrypt.org/staging for testing
//    private static final String ACME_ADDRESS = "acme://pebble"; //for local testing with pebble

    private static final int RENEW_DAYS_LEFT = 10;

    // File name of the CSR
    private static final File CONFIG_FILE = new File("config.json");

    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    public static void main(String... args) {
        if (args.length == 0) {
            System.err.println("Usage: AcmeClient.jar register|renew");
            System.exit(1);
        }

        LOG.info("Starting up...");

        Security.addProvider(new BouncyCastleProvider());

        try {
            switch(args[0].toLowerCase()) {
                case "register":
                    register(args);
                    break;
                case "renew":
                    renew();
                    break;
                default:
                    LOG.error("Please provide a correct mode arg (register/renew)");
            }
        } catch(Exception ex) {
            LOG.error("Failed executing the desired action", ex);
            System.exit(1);
        }
    }

    private static Config getConfig() {
        try {
            return CONFIG_FILE.exists()
                    ? MAPPER.readValue(CONFIG_FILE, Config.class)
                    : null;
        } catch(IOException ex) {
            LOG.error("Error reading the sites file", ex);
            return null;
        }
    }

    private static void register(String[] args) throws IOException, AcmeException {
        if(args.length == 1) {
            LOG.info("Usage: AcmeClient.jar register --override -p /statics/path -d my.domain.com [-d another.domain.com ...] [-p /statics/other -d ...]");
            return;
        }

        Args parsedArgs = new ArgParser().parse(args);

        Config cfg;
        if(!parsedArgs.isOverride() && (cfg = getConfig()) != null && !cfg.getSiteConfigs().isEmpty()) {
            LOG.warn("Detected already existing domain registrations.\n" +
                    "If you want to just renew them, use the renew mode instead of register.\n" +
                    "Otherwise execute the program with the argument \"override\" directly following the register argument.\n" +
                    "Note: this will forget all previously registered domains!");
            return;
        }

        if(!parsedArgs.isQuiet()) {
            StringBuilder sb = new StringBuilder("About to create following certs:\n");
            Map<File, List<SiteConfig>> webroots = parsedArgs.getSiteConfigs().stream().collect(Collectors.groupingBy(SiteConfig::getStaticsDir));
            webroots.forEach((key, value) -> {
                sb.append("Webroot ").append(key.getAbsolutePath()).append('\n');
                value.forEach(site -> {
                    sb.append('\t').append(site.getDomain()).append('\n');
                });
            });
            sb.append("Key file: ").append(parsedArgs.getKeyFile().getAbsolutePath())
                    .append("\nCert file: ").append(parsedArgs.getCertFile().getAbsolutePath());
            sb.append("\nIs this correct?");
            if(!Utils.userConfirmation(sb.toString()))
                return;
        }

        KeyPair userKeyPair = Entities.loadOrCreateAccountKeyPair();

        KeyPair domainKeyPair = Entities.loadOrCreateDomainKeyPair(parsedArgs.getKeyFile());

        requestCert(parsedArgs.getConfig(), userKeyPair, domainKeyPair, parsedArgs.isQuiet());
    }

    private static void renew() throws IOException, AcmeException {
        Config cfg = getConfig();
        if(cfg == null || cfg.getSiteConfigs().isEmpty()) {
            LOG.error("No sites are registered. Can't renew");
            System.exit(1);
        }

        if(Instant.now().until(cfg.getExpiry().toInstant(), ChronoUnit.DAYS) > RENEW_DAYS_LEFT) {
            LOG.info("Nothing to renew");
            System.exit(2);
        }

        if(cfg.getKeyFile() == null || !cfg.getKeyFile().exists())
            throw new AcmeException("Key file does not exist. Aborting renewal");

        KeyPair userKeyPair = Entities.loadAccountKeyPair();
        if(userKeyPair == null)
            throw new AcmeException("No account KeyPair was found. Aborting renewal");

        KeyPair domainKeyPair = Entities.loadDomainKeyPair(cfg.getKeyFile());
        if(domainKeyPair == null)
            throw new AcmeException("No domain KeyPair found. Aborting renewal");

        requestCert(cfg, userKeyPair, domainKeyPair, true);
    }

    private static void requestCert(Config config, KeyPair userKeyPair,
                                    KeyPair domainKeyPair, boolean skipToS) throws AcmeException, IOException {
        Map<String, SiteConfig> requestedDomains = config.getSiteConfigs().stream()
                .collect(Collectors.toMap(SiteConfig::getDomain, Function.identity()));

        Session session = new Session(ACME_ADDRESS);

        Account acct = Entities.findOrRegisterAccount(session, userKeyPair, skipToS);

        LOG.info("Ordering domains");
        Order order = acct.newOrder().domains(requestedDomains.keySet()).create();

        // Perform all required authorizations
        for (Authorization auth : order.getAuthorizations()) {
            Utils.authorize(auth, requestedDomains.get(auth.getDomain()));
        }

        // Generate a CSR for all of the domains, and sign it with the domain key pair.
        CSRBuilder csrb = new CSRBuilder();
        csrb.addDomains(requestedDomains.keySet());
        csrb.sign(domainKeyPair);

        // Order the certificate
        order.execute(csrb.getEncoded());

        // Wait for the order to complete
        try {
            int attempts = 10;
            while (order.getStatus() != Status.VALID && attempts-- > 0) {
                // Did the order fail?
                if (order.getStatus() == Status.INVALID) {
                    throw new AcmeException("Order failed... Giving up.");
                }

                // Wait for a few seconds
                Thread.sleep(3000L);

                // Then update the status
                order.update();
            }
        } catch (InterruptedException ex) {
            LOG.error("interrupted", ex);
            Thread.currentThread().interrupt();
        }

        // Get the certificate
        Certificate certificate = order.getCertificate();
        if(certificate == null)
            throw new AcmeException("Could not get certificate");

        // Write a combined file containing the certificate and chain.
        try (FileWriter fw = new FileWriter(config.getCertFile())) {
            certificate.writeCertificate(fw);
        }

        storeSiteConfigs(config, certificate);

        LOG.info("Success! The certificate for domains " + requestedDomains.keySet() + " has been generated!");
        LOG.debug("Certificate URL: " + certificate.getLocation());
    }

    private static void storeSiteConfigs(Config requests, Certificate certificate) throws IOException {
        requests.setExpiry(certificate.getCertificate().getNotAfter());

        MAPPER.writeValue(CONFIG_FILE, requests);
    }
}
