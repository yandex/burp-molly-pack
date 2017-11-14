package com.yandex.burp.extensions.plugins.config;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.util.List;

/**
 * Created by a-abakumov on 14/02/2017.
 */

public class ContentSniffingPluginConfig {
    @SerializedName("ignoreCodes")
    @Expose
    private List<Integer> ignoreCodes = null;

    public List<Integer> getIgnoreCodes() {
        return ignoreCodes;
    }
}
