package com.yandex.burp.extensions.plugins.audit;

import burp.*;
import com.yandex.burp.extensions.plugins.CustomScanIssue;
import com.yandex.burp.extensions.plugins.config.BurpMollyPackConfig;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

/**
 * Created by a-abakumov on 10/02/2017.
 */
public class WebsocketOriginPlugin implements IAuditPlugin {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private HashSet<String> flags;

    private final int ISSUE_TYPE = 0x080a0009;
    private final String ISSUE_NAME = "Websocket Origin Issue";
    private final String SEVERITY = "Information";
    private final String CONFIDENCE = "Tentative";

    public WebsocketOriginPlugin(IBurpExtenderCallbacks callbacks, BurpMollyPackConfig extConfig) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.flags = new HashSet<>();
    }

    @Override
    public List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        IHttpService httpService = baseRequestResponse.getHttpService();
        IRequestInfo req = helpers.analyzeRequest(baseRequestResponse.getRequest());
        if (req == null) return null;

        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        if (flags.contains(url.toString())) return null;
        else flags.add(url.toString());

        List<IScanIssue> issues = new ArrayList<>();

        List<String> headers = req.getHeaders();
        String headersAll = String.join("\n", headers);
        if (!headersAll.toUpperCase().contains("UPGRADE")
                || !headersAll.toUpperCase().contains("WEBSOCKET"))
            return null;

        Iterator<String> iter = headers.iterator();
        String i;
        while (iter.hasNext()) {
            i = iter.next();
            if (i.contains("Origin:")) {
                iter.remove();
            }
        }

        headers.add("Origin: http://evil.com");

        byte[] body = helpers.stringToBytes(helpers.bytesToString(baseRequestResponse.getRequest()).substring(req.getBodyOffset()));
        byte[] newReq = helpers.buildHttpMessage(headers, body);
        IHttpRequestResponse attack = this.callbacks.makeHttpRequest(httpService, newReq);

        // If response Switching Protocol
        if (helpers.analyzeResponse(attack.getResponse()).getStatusCode() == 101) {
            String issueDetails = "Information system uses Websocket technology. This technology allows you to do cross-domain requests to bypass the Same Origin Policy (SOP)\n" +
                    "Websocket does not verify the Origin, which leads to the possibility to establish a Websocket connection from any Origin.\n" +
                    "IMPORTANT: Need manual verification that connection doesn't uses tokens\n";

            issues.add(new CustomScanIssue(httpService,
                    this.helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    new IHttpRequestResponse[]{this.callbacks.applyMarkers(attack, null, null)},
                    issueDetails, ISSUE_TYPE, ISSUE_NAME, SEVERITY, CONFIDENCE,
                    "", "", ""));
        }
        return issues.isEmpty() ? null : issues;
    }
}
