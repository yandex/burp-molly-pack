package com.yandex.burp.extensions.plugins.config;

/**
 * Created by a-abakumov on 08/02/2017.
 */

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.util.List;

public class BurpMollyPackConfig {

    @SerializedName("activePluginsEnable")
    @Expose
    private List<String> activePluginsEnable;

    public List<String> getActivePluginsEnable() {
        return activePluginsEnable;
    }

    @SerializedName("passivePluginsEnable")
    @Expose
    private List<String> passivePluginsEnable;

    public List<String> getPassivePluginsEnable() {
        return passivePluginsEnable;
    }

    @SerializedName("ClickJackingPlugin")
    @Expose
    private ClickJackingPluginConfig ClickJackingPluginConfig;

    public ClickJackingPluginConfig getClickJackingPluginConfig() {
        return ClickJackingPluginConfig;
    }

    @SerializedName("ContentSniffingPlugin")
    @Expose
    private ContentSniffingPluginConfig ContentSniffingPluginConfig;

    public ContentSniffingPluginConfig getContentSniffingPluginConfig() {
        return ContentSniffingPluginConfig;
    }

    @SerializedName("JsonpPluginPlugin")
    @Expose
    private JsonpPluginConfig JsonpPluginConfig = new JsonpPluginConfig();

    public JsonpPluginConfig getJsonpPluginConfig() {
        return JsonpPluginConfig;
    }
}

