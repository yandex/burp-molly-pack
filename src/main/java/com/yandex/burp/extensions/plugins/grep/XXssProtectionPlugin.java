package com.yandex.burp.extensions.plugins.grep;

import burp.*;
import com.yandex.burp.extensions.plugins.CustomScanIssue;
import com.yandex.burp.extensions.plugins.Utils;
import com.yandex.burp.extensions.plugins.config.BurpMollyPackConfig;

import java.util.Arrays;
import java.util.List;

/**
 * Created by a-abakumov on 15/02/2017.
 */
public class XXssProtectionPlugin implements IGrepPlugin {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private final int ISSUE_TYPE = 0x080a000d;
    private final String ISSUE_NAME = "Missing X-XSS-Protection header";
    private final String SEVERITY = "Information";
    private final String CONFIDENCE = "Certain";


    public XXssProtectionPlugin(IBurpExtenderCallbacks callbacks, BurpMollyPackConfig extConfig) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public IScanIssue grep(IHttpRequestResponse baseRequestResponse) {
        IResponseInfo resp = helpers.analyzeResponse(baseRequestResponse.getResponse());
        if (resp == null) return null;
        if (resp.getStatusCode() != 200) return null;

        List<String> contentTypes = Arrays.asList("text/html", "application/xml");
        List<String> headers = resp.getHeaders();

        String contentTypeHeader = Utils.getContentType(resp);
        if (contentTypeHeader == null) return analyseHeaders(baseRequestResponse, headers);

        if (contentTypes.contains(contentTypeHeader.toLowerCase())) return analyseHeaders(baseRequestResponse, headers);

        return null;
    }

    private IScanIssue analyseHeaders(IHttpRequestResponse baseRequestResponse, List<String> headers) {

        String xXssProtectionHeader = Utils.getHeaderValue(headers, "X-Xss-Protection");
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
        // X-XSS-Protection: 1 Enables XSS filtering (usually default in browsers).
        // If a cross-site scripting attack is detected,
        // the browser will sanitize the page (remove the unsafe parts).
        if (xXssProtectionHeader != null && xXssProtectionHeader.toUpperCase().contains("1")) return null;

        String issueDetails = "The URL <b> " + helpers.analyzeRequest(baseRequestResponse).getUrl().toString() + " </b>\n" +
                "returned an HTTP response without the recommended HTTP header <b>X-XSS-Protection: 1; mode=block</b>";

        return new CustomScanIssue(baseRequestResponse.getHttpService(),
                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                new IHttpRequestResponse[]{this.callbacks.applyMarkers(baseRequestResponse, null, null)},
                issueDetails, ISSUE_TYPE, ISSUE_NAME, SEVERITY, CONFIDENCE,
                "", "", "");
    }
}