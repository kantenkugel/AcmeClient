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

package com.kantenkugel.acmeclient.config;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.File;
import java.util.Date;
import java.util.List;

public class Config {
    public static final File DEFAULT_KEY_FILE = new File("site.key");
    public static final File DEFAULT_CERT_FILE = new File("site.crt");

    private static final int CONFIG_VERSION = 2;

    private int version;

    private List<SiteConfig> siteConfigs;

    private File keyFile;
    private File certFile;

    private Date expiry;

    public Config(List<SiteConfig> siteConfigs, File keyFile, File certFile, Date expiry) {
        this.version = CONFIG_VERSION;
        this.siteConfigs = siteConfigs;
        this.keyFile = keyFile;
        this.certFile = certFile;
        this.expiry = expiry;
    }

    @JsonCreator
    public Config(@JsonProperty("version") int version, @JsonProperty("siteConfigs") List<SiteConfig> siteConfigs,
                  @JsonProperty("keyFile") String keyFile, @JsonProperty("certFile") String certFile, @JsonProperty("expiry") Date expiry) {
        this.version = version == 0 ? 1 : version;
        this.siteConfigs = siteConfigs;
        this.keyFile = keyFile == null ? DEFAULT_KEY_FILE : new File(keyFile);
        this.certFile = certFile == null ? DEFAULT_CERT_FILE : new File(certFile);
        this.expiry = expiry;
    }

    @JsonGetter("keyFile")
    public String getKeyFileStr() {
        return (keyFile == null || keyFile == DEFAULT_KEY_FILE) ? null : keyFile.getAbsolutePath();
    }

    @JsonGetter("certFile")
    public String getCertFileStr() {
        return (certFile == null || certFile == DEFAULT_CERT_FILE) ? null : certFile.getAbsolutePath();
    }

    public int getVersion() {
        return version;
    }

    public List<SiteConfig> getSiteConfigs() {
        return siteConfigs;
    }

    public File getKeyFile() {
        return keyFile;
    }

    public File getCertFile() {
        return certFile;
    }

    public Date getExpiry() {
        return expiry;
    }

    public void setExpiry(Date expiry) {
        this.expiry = expiry;
    }
}
