package com.yandex.burp.extensions.plugins.config;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class MollyConfig {

    @SerializedName("burp-molly-pack")
    @Expose
    private BurpMollyPackConfig BurpMollyPackConfig;
    @SerializedName("burp-active-scanner")
    @Expose
    private BurpActiveScannerConfig BurpActiveScannerConfig;

    public BurpMollyPackConfig getBurpMollyPackConfig() {
        return BurpMollyPackConfig;
    }

    public BurpActiveScannerConfig getBurpActiveScanner() {
        return BurpActiveScannerConfig;
    }

}