package com.yandex.burp.extensions.plugins.audit;

import burp.*;
import com.yandex.burp.extensions.plugins.CustomScanIssue;
import com.yandex.burp.extensions.plugins.Utils;
import com.yandex.burp.extensions.plugins.config.BurpMollyPackConfig;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by a-abakumov on 07/02/2017.
 */
public class YaExpressRedirectPlugin implements IAuditPlugin {

    private static final ArrayList<String> Payloads = new ArrayList<>();

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private HashSet<String> flags;

    private final int ISSUE_TYPE = 0x080a0004;
    private final String ISSUE_NAME = "YaExpress Redirect Issue";
    private final String SEVERITY = "Medium";
    private final String CONFIDENCE = "Certain";

    /*    private final List<String> REDIRECTS = Arrays.asList("//EXAMPLE.COM", "/\\EXAMPLE.COM", "\\/EXAMPLE.COM",
                "HTTPS://EXAMPLE.COM", "HTTP://EXAMPLE.COM",
                // Internet Explorer
                "/\t/EXAMPLE.COM", "\\\t\\EXAMPLE.COM",
                // Chrome
                "///EXAMPLE.COM", "\\/\\EXAMPLE.COM", "/\\/EXAMPLE.COM");
    */
    private static final Pattern REDIRECT_PATTERN = Pattern.compile("^(?:(?:HTTPS?:(?:\\/{2,}|(?:\\\\\\/){2,}))|(?:\\/\\/|\\/\\t\\/|\\/\\\\|\\\\\\t\\\\|\\/\\\\\\/|\\\\\\/\\\\|\\/\\/\\/{1,}))EXAMPLE\\.COM");

    public YaExpressRedirectPlugin(IBurpExtenderCallbacks callbacks, BurpMollyPackConfig extConfig) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.flags = new HashSet<>();
        initPayloads();
    }

    private void initPayloads() {
        Payloads.add("%5cexample.com/%2e%2e");
        Payloads.add("example.com/%2e%2e");
        Payloads.add("%5cexample.com%3f/doc/");
        Payloads.add("%2fexample.com");
        Payloads.add("/%5cexample.com/%2e%2e");
        Payloads.add("/example.com/%2e%2e");
        Payloads.add("/%5cexample.com%3f/doc/");
        Payloads.add("/%2fexample.com");
        Payloads.add("example.com");
    }

    public List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IResponseInfo resp = helpers.analyzeResponse(baseRequestResponse.getResponse());
        IRequestInfo req = helpers.analyzeRequest(baseRequestResponse.getRequest());
        if (resp == null | req == null) return null;

        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        if (flags.contains(url.toString())) return null;
        else flags.add(url.toString());

        List<IScanIssue> issues = new ArrayList<>();
        IHttpService httpService = baseRequestResponse.getHttpService();
        List<String> headers = req.getHeaders();

        for (String i : Payloads) {
            String finalPayload = req.getMethod() + " " + url.getPath() + i + " HTTP/1.1";
            headers.set(0, finalPayload);
            byte[] body = helpers.stringToBytes(helpers.bytesToString(baseRequestResponse.getRequest()).substring(req.getBodyOffset()));
            byte[] modifiedReq = helpers.buildHttpMessage(headers, body);
            IHttpRequestResponse attack = this.callbacks.makeHttpRequest(httpService, modifiedReq);
            IScanIssue res = analyzeResponse(attack);
            if (res != null) issues.add(res);
        }
        if (issues.size() > 0) return issues;
        return issues;
    }

    public IScanIssue analyzeResponse(IHttpRequestResponse requestResponse) {
        IResponseInfo resp = helpers.analyzeResponse(requestResponse.getResponse());
        if (resp == null || resp.getStatusCode() < 300 || resp.getStatusCode() >= 400) return null;
        List<String> headers = resp.getHeaders();

        String locationHeader = Utils.getHeaderValue(headers, "Location");
        if (locationHeader == null) return null;
        Matcher redirectMatcher = REDIRECT_PATTERN.matcher(locationHeader.toUpperCase());
        if (redirectMatcher.find()) {
            String attackDetails = "A open redirect vulnerability was found at: <b>" +
                    helpers.analyzeRequest(requestResponse).getUrl().toString() + "</b>\n";
            List responseMarkers = new ArrayList(1);
            responseMarkers.add(new int[]{helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf("LOCATION"),
                    helpers.bytesToString(requestResponse.getResponse()).toUpperCase().indexOf("LOCATION") + "LOCATION".length()});

            return new CustomScanIssue(requestResponse.getHttpService(),
                    this.helpers.analyzeRequest(requestResponse).getUrl(),
                    new IHttpRequestResponse[]{this.callbacks.applyMarkers(requestResponse, null, responseMarkers)},
                    attackDetails, ISSUE_TYPE, ISSUE_NAME, SEVERITY, CONFIDENCE,
                    "", "", "");
        }
        return null;
    }
}