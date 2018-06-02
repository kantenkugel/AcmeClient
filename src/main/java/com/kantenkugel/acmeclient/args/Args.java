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

import com.kantenkugel.acmeclient.config.Config;
import com.kantenkugel.acmeclient.config.SiteConfig;

import java.io.File;
import java.util.List;

public class Args {
    private boolean override;
    private boolean quiet;
    private List<SiteConfig> siteConfigs;
    private File keyFile;
    private File certFile;

    Args(boolean override, boolean quiet, List<SiteConfig> siteConfigs, File keyFile, File certFile) {
        this.override = override;
        this.quiet = quiet;
        this.siteConfigs = siteConfigs;
        this.keyFile = keyFile == null ? Config.DEFAULT_KEY_FILE : keyFile;
        this.certFile = certFile == null ? Config.DEFAULT_CERT_FILE : certFile;
    }

    public Config getConfig() {
        return new Config(siteConfigs, keyFile, certFile, null);
    }

    public boolean isQuiet() {
        return quiet;
    }

    public boolean isOverride() {
        return override;
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
}
