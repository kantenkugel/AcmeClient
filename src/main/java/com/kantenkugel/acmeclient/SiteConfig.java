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

package com.kantenkugel.acmeclient;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.File;
import java.util.Date;

public class SiteConfig {
    private String domain;
    private File staticsDir;
    private Date expiry;

    @JsonCreator
    public SiteConfig(@JsonProperty("domain") String domain, @JsonProperty("staticsDir") File staticsDir,
                      @JsonProperty("expiry") Date expiry) {
        this.domain = domain;
        this.staticsDir = staticsDir;
        this.expiry = expiry;
    }

    public String getDomain() {
        return domain;
    }

    public File getStaticsDir() {
        return staticsDir;
    }

    public Date getExpiry() {
        return expiry;
    }
}
