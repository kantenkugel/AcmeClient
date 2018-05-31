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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
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

public class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    private static final String ACME_ADDRESS = "acme://letsencrypt.org"; // acme://letsencrypt.org/staging for testing
//    private static final String ACME_ADDRESS = "acme://pebble"; //for local testing with pebble

    // File name of the CSR
    private static final File SITE_CONFIG_FILE = new File("sites.json");

    // File name of the signed certificate
    private static final File DOMAIN_CHAIN_FILE = new File("domain-chain.crt");

    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    /**
     * Invokes this example.
     *
     * @param args
     *            Domains to get a certificate for
     */
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

    private static List<SiteConfig> getSiteConfigs() {
        try {
            return SITE_CONFIG_FILE.exists()
                    ? MAPPER.readValue(SITE_CONFIG_FILE, new TypeReference<List<SiteConfig>>() {
            })
                    : null;
        } catch(IOException ex) {
            LOG.error("Error reading the sites file", ex);
            return null;
        }
    }

    private static void register(String[] args) throws IOException, AcmeException {
        if(args.length == 1) {
            LOG.info("Usage: AcmeClient.jar register [override] -p /statics/path -d my.domain.com [-d another.domain.com ...] [-p /statics/other -d ...]");
            return;
        }

        List<SiteConfig> siteConfigs = getSiteConfigs();
        if(siteConfigs != null && !siteConfigs.isEmpty()) {
            if(!args[1].toLowerCase().equals("override")) {
                LOG.warn("Detected already existing domain registrations.\n" +
                        "If you want to just renew them, use the renew mode instead of register.\n" +
                        "Otherwise execute the program with the argument \"override\" directly following the register argument.\n" +
                        "Note: this will forget all previously registered domains!");
                return;
            }
        }

        TokenMode mode = TokenMode.NONE;
        StringBuilder path = new StringBuilder();
        File filePath = null;
        Map<String, SiteConfig> toRegister = new HashMap<>();

        for(int i=1; i < args.length; i++) {
            if(i==1 && args[1].equalsIgnoreCase("override"))
                continue;
            switch(args[i].toLowerCase()) {
                case "-p":
                    mode = TokenMode.PATH;
                    path.setLength(0);
                    break;
                case "-d":
                    mode = TokenMode.DOMAIN;
                    if(path.length() == 0) {
                        LOG.error("YOu have to specify a webroot path via -p before adding domains!");
                        System.exit(1);
                    }
                    filePath = new File(path.substring(1));
                    if(!filePath.exists() || !filePath.isDirectory()) {
                        LOG.error("File {} does not exist or is not a directory!", filePath.getPath());
                        System.exit(1);
                    }
                    break;
                default:
                    switch(mode) {
                        case NONE:
                            LOG.error("Invalid syntax. run with only register argument for usage example.");
                            System.exit(1);
                            break;
                        case PATH:
                            path.append(' ').append(args[i]);
                            filePath = null;
                            break;
                        case DOMAIN:
                            String domain = args[i].toLowerCase();
                            toRegister.put(domain, new SiteConfig(domain, filePath, null));
                            break;
                    }
            }
        }

        KeyPair userKeyPair = Entities.loadOrCreateAccountKeyPair();

        KeyPair domainKeyPair = Entities.loadOrCreateDomainKeyPair();

        requestCert(toRegister, userKeyPair, domainKeyPair, false);
    }

    private static void renew() throws IOException, AcmeException {
        List<SiteConfig> siteConfigs = getSiteConfigs();
        if(siteConfigs == null || siteConfigs.isEmpty()) {
            LOG.error("No sites are registered. Can't renew");
            System.exit(1);
        }

        if(siteConfigs.stream().noneMatch(config -> Instant.now().until(config.getExpiry().toInstant(), ChronoUnit.DAYS) < 10)) {
            LOG.info("Nothing to renew");
            System.exit(2);
        }

        Map<String, SiteConfig> toRenew = siteConfigs.stream().collect(Collectors.toMap(SiteConfig::getDomain, Function.identity()));

        KeyPair userKeyPair = Entities.loadAccountKeyPair();
        if(userKeyPair == null)
            throw new AcmeException("No account KeyPair was found. Aborting renewal");

        KeyPair domainKeyPair = Entities.loadDomainKeyPair();
        if(domainKeyPair == null)
            throw new AcmeException("No domain KeyPair found. Aborting renewal");

        requestCert(toRenew, userKeyPair, domainKeyPair, true);
    }

    private static void requestCert(Map<String, SiteConfig> requestedDomains, KeyPair userKeyPair,
                                    KeyPair domainKeyPair, boolean skipToS) throws AcmeException, IOException {
        Session session = new Session(ACME_ADDRESS);

        Account acct = Entities.findOrRegisterAccount(session, userKeyPair, skipToS);

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
        try (FileWriter fw = new FileWriter(DOMAIN_CHAIN_FILE)) {
            certificate.writeCertificate(fw);
        }

        storeSiteConfigs(requestedDomains.values(), certificate);

        LOG.info("Success! The certificate for domains " + requestedDomains.keySet() + " has been generated!");
        LOG.info("Certificate URL: " + certificate.getLocation());
    }

    private static void storeSiteConfigs(Collection<SiteConfig> requests, Certificate certificate) throws IOException {
        List<SiteConfig> configs = new ArrayList<>(requests.size());
        Date expiry = certificate.getCertificate().getNotAfter();
        for(SiteConfig request : requests) {
            configs.add(new SiteConfig(request.getDomain(), request.getStaticsDir(), expiry));
        }
        MAPPER.writeValue(SITE_CONFIG_FILE, configs);
    }

    private enum TokenMode {
        NONE, PATH, DOMAIN
    }
}
