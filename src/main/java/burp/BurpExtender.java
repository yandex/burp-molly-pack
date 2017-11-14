package burp;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import com.yandex.burp.extensions.plugins.audit.IAuditPlugin;
import com.yandex.burp.extensions.plugins.config.BurpMollyPackConfig;
import com.yandex.burp.extensions.plugins.config.MollyConfig;
import com.yandex.burp.extensions.plugins.grep.IGrepPlugin;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


public class BurpExtender implements IBurpExtender, IScannerCheck, IExtensionStateListener {

    public static OutputStream stdout;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private MollyConfig extConfig;
    private List<String> activePluginsNames;
    private List<IAuditPlugin> activePlugins;
    private List<String> passivePluginsNames;
    private List<IGrepPlugin> passivePlugins;

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Burp Molly Pack");

        // obtain our output stream
        stdout = callbacks.getStdout();

        Map<String, String> env = System.getenv();
        String configPath = env.get("MOLLY_CONFIG");

        if (configPath == null) {
            configPath = "burp_molly_config.json";
        }

        try {
            println("Trying to load config from " + Paths.get(configPath).toAbsolutePath().toString());
            String configJSON = new String(Files.readAllBytes(Paths.get(configPath)), StandardCharsets.UTF_8);
            extConfig = new Gson().fromJson(configJSON, MollyConfig.class);
        } catch (IOException e) {
            println("Error loading extension config");
            return;
        } catch (JsonParseException e) {
            println("Error loading extension config");
            return;
        }

        BurpMollyPackConfig burpMollyPackConfig = extConfig.getBurpMollyPackConfig();
        if (burpMollyPackConfig == null) {
            println("Error loading burpMollyPackConfig");
            callbacks.exitSuite(false);
        }
        //
        //Check that we have at least one active plugin
        //
        if (burpMollyPackConfig.getActivePluginsEnable() != null) {
            this.activePluginsNames = burpMollyPackConfig.getActivePluginsEnable();
            this.activePlugins = new ArrayList<>();

            for (String activePluginName : activePluginsNames) {
                try {
                    Constructor iAuditPluginConstructor = null;
                    try {
                        iAuditPluginConstructor = Class
                                .forName("com.yandex.burp.extensions.plugins.audit." + activePluginName)
                                .getConstructor(IBurpExtenderCallbacks.class, BurpMollyPackConfig.class);
                    } catch (ClassNotFoundException e) {
                        e.printStackTrace();
                    }
                    try {
                        activePlugins.add((IAuditPlugin) iAuditPluginConstructor.newInstance(this.callbacks, burpMollyPackConfig));
                    } catch (NullPointerException | InstantiationException | InvocationTargetException | IllegalAccessException e) {
                        e.printStackTrace();
                    }
                } catch (NoSuchMethodException e) {
                    e.printStackTrace();
                }
            }
        }
        //
        //Check that we have at least one active plugin
        //
        if (burpMollyPackConfig.getPassivePluginsEnable() != null) {
            this.passivePluginsNames = burpMollyPackConfig.getPassivePluginsEnable();
            this.passivePlugins = new ArrayList<>();

            for (String passivePluginName : passivePluginsNames) {
                try {
                    Constructor iGrepPluginConstructor = null;
                    try {
                        iGrepPluginConstructor = Class
                                .forName("com.yandex.burp.extensions.plugins.grep." + passivePluginName)
                                .getConstructor(IBurpExtenderCallbacks.class, BurpMollyPackConfig.class);
                    } catch (ClassNotFoundException e) {
                        e.printStackTrace();
                    }
                    try {
                        passivePlugins.add((IGrepPlugin) iGrepPluginConstructor.newInstance(this.callbacks, burpMollyPackConfig));
                    } catch (NullPointerException | InstantiationException | InvocationTargetException | IllegalAccessException e) {
                        e.printStackTrace();
                    }
                } catch (NoSuchMethodException e) {
                    e.printStackTrace();
                }
            }
        }

        println("Extension was loaded");

        callbacks.registerScannerCheck(this);

        // register ourselves as an extension state listener
        callbacks.registerExtensionStateListener(this);

    }

    //
    // implement IExtensionStateListener
    //
    @Override
    public void extensionUnloaded() {
        println("Extension was unloaded");
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        List<IScanIssue> results = new ArrayList<>();
        List<IScanIssue> res;

        for (IAuditPlugin activePlugin : activePlugins) {
            res = activePlugin.doScan(baseRequestResponse, insertionPoint);
            if (res != null) results.addAll(res);
        }

        if (results.size() > 0) return results;
        return null;

    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {

        List<IScanIssue> results = new ArrayList<>();
        IScanIssue res;

        for (IGrepPlugin passivePlugin : passivePlugins) {
            res = passivePlugin.grep(baseRequestResponse);
            if (res != null) results.add(res);
        }

        if (results.size() > 0) return results;
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        switch (newIssue.getIssueName()) {
            case "Clickjacking":
            case "Missing X-Content-Type-Options header":
            case "Missing X-XSS-Protection header":
            case "Content Security Policy related information":
                if (existingIssue.getIssueName().equals(newIssue.getIssueName())
                        && existingIssue.getUrl().getHost().equals(newIssue.getUrl().getHost())
                        && existingIssue.getUrl().getPath().equals(newIssue.getUrl().getPath())) {
                    return -1;
                }
                return 0;
            default:
                if (existingIssue.getIssueDetail().equals(newIssue.getIssueDetail())) {
                    return -1;
                }
                return 0;
        }
    }

    public static void println(String toPrint) {
        try {
            stdout.write(toPrint.getBytes());
            stdout.write("\n".getBytes());
            stdout.flush();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

}