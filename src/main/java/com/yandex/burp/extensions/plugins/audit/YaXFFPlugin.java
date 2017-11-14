package com.yandex.burp.extensions.plugins.audit;

import burp.*;
import com.yandex.burp.extensions.plugins.CustomScanIssue;
import com.yandex.burp.extensions.plugins.config.BurpMollyPackConfig;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

/**
 * Created by a-abakumov on 03/03/2017.
 */
public class YaXFFPlugin implements IAuditPlugin {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private HashSet<String> flags;

    private static final List<String> HEADER_NAMES = Arrays.asList("X-Real-IP", "X-Forwarded-For", "X-Forwarded-For-Y");
    private static final String HEADER_VALUE = "127.0.0.1";
    private static final List<String> STATUS_PATH = Arrays.asList("status", "server-status", "/status", "/server-status");

    private final int ISSUE_TYPE = 0x080a0008;
    private final String ISSUE_NAME = "YaXFF Molly";
    private final String SEVERITY = "Medium";
    private final String CONFIDENCE = "Certain";

    public YaXFFPlugin(IBurpExtenderCallbacks callbacks, BurpMollyPackConfig extConfig) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.flags = new HashSet<>();
    }

    @Override
    public List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        IResponseInfo resp = helpers.analyzeResponse(baseRequestResponse.getResponse());
        IRequestInfo req = helpers.analyzeRequest(baseRequestResponse.getRequest());
        if (resp == null | req == null) return null;

        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        if (flags.contains(url.toString())) return null;
        else flags.add(url.toString());

        List<IScanIssue> issues = new ArrayList<>();

        for (String status : STATUS_PATH) {
            List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();

            for (String i : HEADER_NAMES) {
                headers.removeIf(header -> header != null && header.toLowerCase().startsWith(i.toLowerCase()));
                headers.add(i + ": " + HEADER_VALUE);
            }

            String finalPayload = req.getMethod() + " " + url.getPath() + status + " HTTP/1.1";
            headers.set(0, finalPayload);
            byte[] attackReq = helpers.buildHttpMessage(headers, null);
            IHttpRequestResponse attackRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), attackReq);

            if (helpers.analyzeResponse(attackRequestResponse.getResponse()).getStatusCode() != 404
                    && helpers.bytesToString(attackRequestResponse.getResponse()).toLowerCase().contains("connections")) {

                String attackDetails = "Restriction bypass was found at:\n<b>" + helpers.analyzeRequest(attackRequestResponse).getUrl() +
                        "</b>";

                List responseMarkers = new ArrayList(1);
                responseMarkers.add(new int[]{helpers.bytesToString(attackRequestResponse.getResponse()).toLowerCase().indexOf("connections"),
                        helpers.bytesToString(attackRequestResponse.getResponse()).toLowerCase().indexOf("connections") + "connections".length()});

                issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        new IHttpRequestResponse[]{callbacks.applyMarkers(attackRequestResponse, null, responseMarkers)},
                        attackDetails, ISSUE_TYPE, ISSUE_NAME, SEVERITY, CONFIDENCE,
                        "", "", ""));
            }
        }
        return issues.isEmpty() ? null : issues;
    }
}