package com.yandex.burp.extensions.plugins.audit;

import burp.*;
import com.yandex.burp.extensions.plugins.CustomScanIssue;
import com.yandex.burp.extensions.plugins.config.BurpMollyPackConfig;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/**
 * Created by a-abakumov on 06/02/2017.
 */
public class YaExpressExceptionPlugin implements IAuditPlugin {

    private static final ArrayList<String> Signatures = new ArrayList<>();
    private static final ArrayList<String> UrlencodeCases = new ArrayList<>();
    private static final ArrayList<String> CharsetCases = new ArrayList<>();

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private HashSet<String> flags;

    private final int ISSUE_TYPE = 0x080a0003;
    private final String ISSUE_NAME = "YaExpress Exception Issue";
    private final String SEVERITY = "Low";
    private final String CONFIDENCE = "Certain";

    public YaExpressExceptionPlugin(IBurpExtenderCallbacks callbacks, BurpMollyPackConfig extConfig) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.flags = new HashSet<>();
        initCharsetCases();
        initSignatures();
        initUrlencodeCases();
    }

    private void initSignatures() {
        Signatures.add("UnsupportedMediaTypeError:");
        Signatures.add("TypeError:");
        Signatures.add("Trace");
    }

    private void initUrlencodeCases() {
        UrlencodeCases.add("..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c");
        UrlencodeCases.add("..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cwindows\\win.ini");
        UrlencodeCases.add("%d");
    }

    private void initCharsetCases() {
        CharsetCases.add("application/x-www-form-urlencoded; charset=give_me_exception");
        CharsetCases.add("application/json; charset=give_me_exception");
    }

    public List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IRequestInfo req = helpers.analyzeRequest(baseRequestResponse.getRequest());
        if (req == null) return null;

        List<IScanIssue> issues = new ArrayList<>();
        IHttpService httpService = baseRequestResponse.getHttpService();
        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        if (flags.contains(req.getMethod() + url.toString())) return null;
        else flags.add(req.getMethod() + url.toString());
        List<String> headers = req.getHeaders();

        for (String i : CharsetCases) {
            headers.removeIf(header -> header != null && header.toLowerCase().startsWith("content-type"));
            headers.add("Content-type: " + i);
            byte[] body;
            if (helpers.bytesToString(baseRequestResponse.getRequest()).length() > req.getBodyOffset()) {
                body = helpers.stringToBytes(helpers.bytesToString(baseRequestResponse.getRequest()).substring(req.getBodyOffset()));
                IHttpRequestResponse attack = this.callbacks.makeHttpRequest(httpService, helpers.buildHttpMessage(headers, body));
                IScanIssue res = analyzeResponse(attack);
                if (res != null) issues.add(res);
            } else {
                IHttpRequestResponse attack = this.callbacks.makeHttpRequest(httpService, helpers.buildHttpMessage(headers, "".getBytes()));
                IScanIssue res = analyzeResponse(attack);
                if (res != null) issues.add(res);
            }

        }
        for (String i : UrlencodeCases) {
            String finalPayload = req.getMethod() + " " + url.getPath() + "\\" + i + " HTTP/1.1";
            headers.set(0, finalPayload);
            byte[] body = helpers.stringToBytes(helpers.bytesToString(baseRequestResponse.getRequest()).substring(req.getBodyOffset()));
            byte[] modifiedReq = helpers.buildHttpMessage(headers, body);
            IHttpRequestResponse attack = this.callbacks.makeHttpRequest(httpService, modifiedReq);
            IScanIssue res = analyzeResponse(attack);
            if (res != null) issues.add(res);
        }

        if (issues.size() > 0) return issues;
        return null;
    }

    public IScanIssue analyzeResponse(IHttpRequestResponse requestResponse) {
        if (requestResponse.getResponse() == null) return null;

        for (String i : Signatures) {
            if (helpers.bytesToString(requestResponse.getResponse()).contains(i)) {

                List responseMarkers = new ArrayList(1);
                responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).indexOf(i),
                        helpers.bytesToString(requestResponse.getResponse()).indexOf(i) + i.length()});
                String attackDetails = "A exception with information disclosure was found at: <b>" +
                        helpers.analyzeRequest(requestResponse).getUrl().toString() + "</b>\n";
                return new CustomScanIssue(requestResponse.getHttpService(),
                        this.helpers.analyzeRequest(requestResponse).getUrl(),
                        new IHttpRequestResponse[]{this.callbacks.applyMarkers(requestResponse, null, responseMarkers)},
                        attackDetails, ISSUE_TYPE, ISSUE_NAME, SEVERITY, CONFIDENCE,
                        "", "", "");
            }
        }
        return null;
    }
}
