package com.yandex.burp.extensions.plugins.grep;


import burp.*;
import com.yandex.burp.extensions.plugins.CustomScanIssue;
import com.yandex.burp.extensions.plugins.Utils;
import com.yandex.burp.extensions.plugins.config.BurpMollyPackConfig;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by a-abakumov on 02/02/2017.
 */
//
// This plugin greps every page for X-Frame-Options header
//
public class ClickJackingPlugin implements IGrepPlugin {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private List<Integer> ignoreCodes = new ArrayList<>();

    private final int ISSUE_TYPE = 0x080a000b;
    private final String ISSUE_NAME = "Clickjacking";
    private final String SEVERITY = "Information";
    private final String CONFIDENCE = "Certain";

    public ClickJackingPlugin(IBurpExtenderCallbacks callbacks, BurpMollyPackConfig extConfig) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        if (extConfig.getClickJackingPluginConfig() == null) throw new NullPointerException();
        this.ignoreCodes = extConfig.getClickJackingPluginConfig().getIgnoreCodes();
    }

    @Override
    public IScanIssue grep(IHttpRequestResponse baseRequestResponse) {
        IResponseInfo resp = helpers.analyzeResponse(baseRequestResponse.getResponse());
        if (resp == null) return null;

        List<String> headers = resp.getHeaders();

        short statusCode = resp.getStatusCode();
        if (ignoreCodes != null && ignoreCodes.contains(new Integer(statusCode))) return null;

        String contentTypeHeader = Utils.getContentType(resp);
        if (contentTypeHeader != null && !contentTypeHeader.toUpperCase().contains("TEXT/HTML")) return null;

        String xFrameOptionsHeader = Utils.getHeaderValue(headers, "X-Frame-Options");
        if (xFrameOptionsHeader == null) {

            String issueDetails = "Vulnerability detected at <b> " + helpers.analyzeRequest(baseRequestResponse).getUrl().toString() + "</b>\n" +
                    "X-FRAME-OPTIONS: doesn't exists";

            return new CustomScanIssue(baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    new IHttpRequestResponse[]{this.callbacks.applyMarkers(baseRequestResponse, null, null)},
                    issueDetails, ISSUE_TYPE, ISSUE_NAME, SEVERITY, CONFIDENCE,
                    "", "", "");
        }

        if (!xFrameOptionsHeader.toUpperCase().contains("DENY") && !xFrameOptionsHeader.toUpperCase().contains("SAMEORIGIN")) {

            String issueDetails = "Vulnerability detected at <b> " + helpers.analyzeRequest(baseRequestResponse).getUrl().toString() + "</b>\n" +
                    "X-FRAME-OPTIONS: exists, but doesn't contains DENY or SAMEORIGIN value";
            List responseMarkers = new ArrayList(1);
            String responseString = helpers.bytesToString(baseRequestResponse.getResponse());

            responseMarkers.add(new int[]{responseString.toUpperCase().indexOf("X-FRAME-OPTIONS:"),
                    responseString.toUpperCase().indexOf("X-FRAME-OPTIONS:") + "X-FRAME-OPTIONS:".length()});

            return new CustomScanIssue(baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    new IHttpRequestResponse[]{this.callbacks.applyMarkers(baseRequestResponse, null, responseMarkers)},
                    issueDetails, ISSUE_TYPE, ISSUE_NAME, SEVERITY, CONFIDENCE,
                    "", "", "");
        }

        return null;
    }
}
