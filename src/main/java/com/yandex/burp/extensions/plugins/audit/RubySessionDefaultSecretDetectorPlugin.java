package com.yandex.burp.extensions.plugins.audit;

import burp.*;
import com.yandex.burp.extensions.plugins.CustomScanIssue;
import com.yandex.burp.extensions.plugins.config.BurpMollyPackConfig;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Formatter;
import java.util.HashSet;
import java.util.List;

/**
 * Created by ezaitov on 07.02.2017.
 */
public class RubySessionDefaultSecretDetectorPlugin implements IAuditPlugin {
    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final int keyIterNum = 1000;
    private static final int keySize = 64;
    private static final String salt = "signed encrypted cookie";

    private final int ISSUE_TYPE = 0x080a000a;
    private final String ISSUE_NAME = "Ruby Session Default Secret";
    private final String SEVERITY = "Critical";
    private final String CONFIDENCE = "Certain";

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private HashSet<String> flags;
    private byte[] secretKey;
    private byte[] secretToken;

    public RubySessionDefaultSecretDetectorPlugin(IBurpExtenderCallbacks callbacks, BurpMollyPackConfig extConfig) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.flags = new HashSet<>();
        setSecretKey("anything");
    }

    @Override
    public List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        IResponseInfo resp = helpers.analyzeResponse(baseRequestResponse.getResponse());
        if (resp == null) return null;

        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        if (flags.contains(url.toString())) return null;
        else flags.add(url.toString());

        List<IScanIssue> issues = new ArrayList<>();

        for (ICookie c : resp.getCookies()) {
            if (!c.getValue().contains("--")) continue;
            String[] cookieVal = c.getValue().split("--");
            if (cookieVal.length != 2) continue;
            if (isSignatureValid(cookieVal[0], cookieVal[1])) {
                String issueDetails = "Vulnerability detected at <b> " + helpers.analyzeRequest(baseRequestResponse).getUrl().toString() + "</b>\n" +
                        "Default Ruby Session secret used - can lead to RCE during unmarshalling";
                List responseMarkers = new ArrayList(1);
                String responseString = helpers.bytesToString(baseRequestResponse.getResponse());
                responseMarkers.add(new int[]{responseString.toUpperCase().indexOf("SET-COOKIE:"),
                        responseString.toUpperCase().indexOf("SET-COOKIE:") + "SET-COOKIE:".length()});

                issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        new IHttpRequestResponse[]{this.callbacks.applyMarkers(baseRequestResponse, null, responseMarkers)},
                        issueDetails, ISSUE_TYPE, ISSUE_NAME, SEVERITY, CONFIDENCE,
                        "", "", ""));
            }
        }
        return issues.isEmpty() ? null : issues;
    }

    private void setSecretKey(String value) {
        value = "aeb977de013ade650b97e0aa5246813591104017871a7753fe186e9634c9129b367306606878985c759ca4fddd17d955207011bb855ef01ed414398b4ac8317b";
//        value = "3eb6db5a9026c547c72708438d496d942e976b252138db7e4e0ee5edd7539457d3ed0fa02ee5e7179420ce5290462018591adaf5f42adcf855da04877827def2";
        this.secretToken = helpers.stringToBytes(value);
        try {
            PBEKeySpec spec = new PBEKeySpec(value.toCharArray(), salt.getBytes(), keyIterNum, keySize);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            this.secretKey = skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException e) {
            /* do nothing */
        } catch (InvalidKeySpecException e) {
            /* do nothing */
        }
    }

    private static String toHexString(byte[] bytes) {
        Formatter formatter = new Formatter();

        for (byte b : bytes) {
            formatter.format("%02x", b);
        }

        return formatter.toString();
    }

    private boolean isSignatureValid(String data, String signature) {
        boolean detected = false;
        if (secretKey != null) {
            try {
                SecretKeySpec signingKey = new SecretKeySpec(secretKey, HMAC_SHA1_ALGORITHM);
                Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
                mac.init(signingKey);
                byte[] digest = mac.doFinal(helpers.stringToBytes(data));
                detected = toHexString(digest).equals(signature);
            } catch (InvalidKeyException e) {
                /**/
            } catch (NoSuchAlgorithmException e) {
                /**/
            }
        }
        if (secretToken != null) {
            try {
                SecretKeySpec signingKey = new SecretKeySpec(secretToken, HMAC_SHA1_ALGORITHM);
                Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
                mac.init(signingKey);
                byte[] digest = mac.doFinal(helpers.stringToBytes(data));
                detected = toHexString(digest).equals(signature);
            } catch (InvalidKeyException e) {
                /**/
            } catch (NoSuchAlgorithmException e) {
                /**/
            }
        }

        return detected;
    }
}
