package com.yandex.burp.extensions.plugins.audit;


import burp.*;
import com.yandex.burp.extensions.plugins.CustomScanIssue;
import com.yandex.burp.extensions.plugins.Utils;
import com.yandex.burp.extensions.plugins.config.BurpMollyPackConfig;
import com.yandex.burp.extensions.plugins.config.JsonpPluginConfig;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;


public class JsonpPlugin implements IAuditPlugin {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private final int ISSUE_TYPE = 0x080a0005;
    private final String ISSUE_NAME = "JsonpPlugin";
    private final String SEVERITY = "Medium";
    private final String CONFIDENCE = "Certain";

    private List<String> callbackNames;
    private static final int BODY_SAMPLE_LEN = 210;
    private List<String> payloads = Arrays.asList("()", "`", ".=");
    private List<String> validTypes = Arrays.asList("text/javascript", "application/x-javascript", "application/javascript", "text/plain");
    // Do we need all possible JS types?
    // Firefox uses these (see nsContentUtils::IsJavascriptMIMEType):
    // text/javascript, text/ecmascript, application/javascript, application/ecmascript, application/x-javascript,
    // application/x-ecmascript, text/javascript1.0, text/javascript1.1, text/javascript1.2, text/javascript1.3,
    // text/javascript1.4, text/javascript1.5, text/jscript, text/livescript, text/x-ecmascript, text/x-javascript


    public JsonpPlugin(IBurpExtenderCallbacks callbacks, BurpMollyPackConfig extConfig) {
        JsonpPluginConfig config = extConfig.getJsonpPluginConfig();

        if (config == null)
            throw new NullPointerException();

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.callbackNames = config.getCallbacks();
    }

    @Override
    public List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        if (insertionPoint.getInsertionPointType() != IScannerInsertionPoint.INS_PARAM_URL)
            return null;

        if (!callbackNames.contains(insertionPoint.getInsertionPointName()))
            return null;

        IResponseInfo resp = helpers.analyzeResponse(baseRequestResponse.getResponse());
        IRequestInfo req = helpers.analyzeRequest(baseRequestResponse.getRequest());
        if (resp == null || req == null || resp.getStatusCode() != 200)
            return null;

        String contentTypeHeader = Utils.getContentType(resp);
        if (!validTypes.contains(contentTypeHeader.toLowerCase()))
            return null;

        String bodySample = extractPrefix(helpers.bytesToString(Arrays.copyOfRange(
                baseRequestResponse.getResponse(), resp.getBodyOffset(), resp.getBodyOffset() + BODY_SAMPLE_LEN
        )));
        if (!bodySample.contains(insertionPoint.getBaseValue()))
            return null;

        List<IScanIssue> issues = new ArrayList<>();
        for (String vector : payloads) {
            String payload = insertionPoint.getBaseValue() + vector + UUID.randomUUID().toString().substring(0, 8);
            IHttpRequestResponse payloadedResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(),
                    insertionPoint.buildRequest(helpers.stringToBytes(payload))
            );

            IScanIssue res = analyzeResponse(payloadedResponse, payload);
            if (res != null) {
                issues.add(res);
                break;
            }
        }

        return issues.isEmpty() ? null : issues;
    }

    private IScanIssue analyzeResponse(IHttpRequestResponse requestResponse, String payload) {
        IResponseInfo resp = helpers.analyzeResponse(requestResponse.getResponse());
        if (resp == null || resp.getStatusCode() != 200)
            return null;

        String bodySample = extractPrefix(helpers.bytesToString(Arrays.copyOfRange(
                requestResponse.getResponse(), resp.getBodyOffset(), resp.getBodyOffset() + BODY_SAMPLE_LEN
        )));

        int payloadIndex = bodySample.indexOf(payload);
        if (payloadIndex > -1) {
            String attackDetails = "JSONP callback injection was found at: <b>" +
                    helpers.analyzeRequest(requestResponse).getUrl().toString() + "</b>\n";

            List<int[]> responseMarkers = Arrays.asList(new int[]{
                    resp.getBodyOffset() + payloadIndex, resp.getBodyOffset() + payloadIndex + payload.length()
            });

            return new CustomScanIssue(requestResponse.getHttpService(),
                    helpers.analyzeRequest(requestResponse).getUrl(),
                    new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, null, responseMarkers)},
                    attackDetails, ISSUE_TYPE, ISSUE_NAME, SEVERITY, CONFIDENCE,
                    "", "", "");
        }
        return null;
    }

    private String extractPrefix(String body) {
        int squote = body.indexOf("'");
        int dquote = body.indexOf("\"");
        if (squote == -1 && dquote == -1)
            return body;
        if (squote == -1)
            return body.substring(0, dquote);
        return body.substring(0, squote);
    }
}
