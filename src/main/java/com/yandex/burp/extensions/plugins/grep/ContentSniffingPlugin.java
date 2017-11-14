package com.yandex.burp.extensions.plugins.grep;

import burp.*;
import com.yandex.burp.extensions.plugins.CustomScanIssue;
import com.yandex.burp.extensions.plugins.Utils;
import com.yandex.burp.extensions.plugins.config.BurpMollyPackConfig;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Created by a-abakumov on 07/02/2017.
 */
public class ContentSniffingPlugin implements IGrepPlugin {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private List<Integer> ignoreCodes = new ArrayList<>();

    private final int ISSUE_TYPE = 0x080a000c;
    private final String ISSUE_NAME = "Missing X-Content-Type-Options header";
    private final String SEVERITY = "Information";
    private final String CONFIDENCE = "Certain";

    public ContentSniffingPlugin(IBurpExtenderCallbacks callbacks, BurpMollyPackConfig extConfig) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        if (extConfig.getContentSniffingPluginConfig() == null) throw new NullPointerException();
        this.ignoreCodes = extConfig.getContentSniffingPluginConfig().getIgnoreCodes();
    }

    @Override
    public IScanIssue grep(IHttpRequestResponse baseRequestResponse) {
        IResponseInfo resp = helpers.analyzeResponse(baseRequestResponse.getResponse());
        if (resp == null) return null;

        short statusCode = resp.getStatusCode();

        if (ignoreCodes != null && ignoreCodes.contains(new Integer(statusCode))) return null;

        List<String> contentTypes = Arrays.asList("application/javascript", "text/css", "image/gif", "text/html",
                "image/x-icon", "image/png", "image/jpg", "image/jpeg", "application/x-javascript");
        List<String> headers = resp.getHeaders();

        String xContentTypeOptionsHeader = Utils.getHeaderValue(headers, "X-Content-Type-Options");
        if (xContentTypeOptionsHeader != null && xContentTypeOptionsHeader.toUpperCase().contains("NOSNIFF"))
            return null;

        String contentTypeHeader = Utils.getContentType(resp);
        if (contentTypeHeader != null && !contentTypes.contains(contentTypeHeader.toLowerCase())) return null;

        String issueDetails = "The URL <b> " + helpers.analyzeRequest(baseRequestResponse).getUrl().toString() + "</b>\n" +
                "returned an HTTP response without the recommended HTTP header X-Content-Type-Options";

        return new CustomScanIssue(baseRequestResponse.getHttpService(),
                helpers.analyzeRequest(baseRequestResponse).getUrl(),
                new IHttpRequestResponse[]{this.callbacks.applyMarkers(baseRequestResponse, null, null)},
                issueDetails, ISSUE_TYPE, ISSUE_NAME, SEVERITY, CONFIDENCE,
                "", "", "");
    }
}
