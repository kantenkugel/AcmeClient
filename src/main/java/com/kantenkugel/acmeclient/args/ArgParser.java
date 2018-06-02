/*
 * Copyright 2018 Michael "Kantenkugel" Ritter
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.kantenkugel.acmeclient.args;

import com.kantenkugel.acmeclient.config.SiteConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class ArgParser {
    private static final Logger LOG = LoggerFactory.getLogger(ArgParser.class);

    private StringBuilder stringCollector = new StringBuilder();
    private File webroot, keyFile, certFile;
    private List<SiteConfig> sites;

    public Args parse(String[] args) {
        reset();

        boolean override = false;
        boolean quiet = false;
        TokenMode mode = TokenMode.NONE;

        for(int i=1; i < args.length; i++) {
            switch(args[i].toLowerCase()) {
                case "--override":
                    handleLastMode(mode);
                    override = true;
                    break;
                case "-q":
                case "--quiet":
                    handleLastMode(mode);
                    quiet = true;
                    break;
                case "-k":
                case "--key":
                    handleLastMode(mode);
                    mode = TokenMode.KEY_FILE;
                    break;
                case "-c":
                case "--cert":
                    handleLastMode(mode);
                    mode = TokenMode.CERT_FILE;
                    break;
                case "-w":
                case "--webroot":
                    handleLastMode(mode);
                    mode = TokenMode.WEBROOT;
                    break;
                case "-d":
                case "--domain":
                    handleLastMode(mode);
                    mode = TokenMode.DOMAIN;
                    break;
                default:
                    switch(mode) {
                        case NONE:
                            LOG.error("Invalid syntax. run with only register argument for usage example.");
                            System.exit(1);
                            break;
                        case WEBROOT:
                        case DOMAIN:
                        case KEY_FILE:
                        case CERT_FILE:
                            stringCollector.append(' ').append(args[i]);
                            break;
                    }
            }
        }
        handleLastMode(mode);
        return new Args(override, quiet, sites, keyFile, certFile);
    }

    private void reset() {
        sites = new ArrayList<>();
        stringCollector.setLength(0);
        webroot = keyFile = certFile = null;
    }

    private void handleLastMode(TokenMode mode) {
        switch(mode) {
            case WEBROOT:
                webroot = parsePath("webroot", false);
                break;
            case KEY_FILE:
                keyFile = parsePath("keyFile", true, false);
                break;
            case CERT_FILE:
                certFile = parsePath("certFile", true, false);
            break;
            case DOMAIN:
                if(webroot == null) {
                    LOG.error("You must first declare a webroot before being able to define domains");
                    System.exit(1);
                }
                sites.add(new SiteConfig(getString("domain"), webroot));
            break;
            case NONE:
                break;
        }
    }

    private String getString(String modeName) {
        if(stringCollector.length() == 0) {
            LOG.error("Flag {} requires additional input", modeName);
            System.exit(1);
        }
        String out = stringCollector.substring(1);
        stringCollector.setLength(0);
        return out;
    }

    private File parsePath(String modeName, boolean isFile) {
        return parsePath(modeName, isFile, true);
    }

    private File parsePath(String modeName, boolean isFile, boolean isRequired) {
        File tmp = new File(getString(modeName));
        if(isRequired && (!tmp.exists() || (isFile && !tmp.isFile()) || (!isFile && !tmp.isDirectory()))) {
            LOG.error("File/Folder {} does not exist or is of wrong type!", tmp.getPath());
            System.exit(1);
        }
        return tmp;
    }

    private enum TokenMode {
        NONE, WEBROOT, DOMAIN, KEY_FILE, CERT_FILE
    }
}
