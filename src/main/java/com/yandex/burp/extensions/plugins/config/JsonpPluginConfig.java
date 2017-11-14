package com.yandex.burp.extensions.plugins.config;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.util.Arrays;
import java.util.List;

public class JsonpPluginConfig {
    @SerializedName("callbacks")
    @Expose
    private List<String> callbacks = Arrays.asList("callback", "cb", "jsonp");

    public List<String> getCallbacks() {
        return callbacks;
    }
}
