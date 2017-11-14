package com.yandex.burp.extensions.plugins.audit;

import burp.*;
import com.yandex.burp.extensions.plugins.CustomScanIssue;
import com.yandex.burp.extensions.plugins.config.BurpMollyPackConfig;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by a-abakumov on 03/02/2017.
 */

public class CRLFPlugin implements IAuditPlugin {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private HashSet<String> flags;

    private final int ISSUE_TYPE_CRLF = 0x080a0000;
    private final String ISSUE_NAME_CRLF = "ResponseHeaderInjection(CRLF)";
    private final String SEVERITY_CRLF = "Medium";
    private final String CONFIDENCE_CRLF = "Certain";
    private final String ISSUE_BACKGROUND_CRLF = "HTTP response splitting occurs when:<br/><ul>\" +\n" +
            "\"<li>Data enters a web application through an untrusted source, most frequently an HTTP request.</li>\\n\" +\n" +
            "\"<li>The data is included in an HTTP response header sent to a web user without being validated for malicious characters.</li></ul>\\n\" +\n" +
            "\"HTTP response splitting is a means to an end, not an end in itself. At its root, the attack is straightforward: \\n\" +\n" +
            "\"an attacker passes malicious data to a vulnerable application, and the application includes the data in an HTTP response header.<br/><br/>\\n\" +\n" +
            "\"To mount a successful exploit, the application must allow input that contains CR (carriage return, also given by %0d or \\\\r) \\n\" +\n" +
            "\"and LF (line feed, also given by %0a or \\\\n)characters into the header AND the underlying platform must be vulnerable to the injection\\n\" +\n" +
            "\"of such characters. These characters not only give attackers control of the remaining headers and body of the response the application intends\"+\n" +
            "\"to send, but also allow them to create additional responses entirely under their control.<br/><br/>\\n\" +\n" +
            "\"The example below uses a Java example, but this issue has been fixed in virtually all modern Java EE application servers.\" +\n" +
            "\"If you are concerned about this risk, you should test on the platform of concern to see if the underlying platform allows for CR or LF characters\"+\n" +
            "\"to be injected into headers. We suspect that, in general, this vulnerability has been fixed in most modern application servers, regardless of what language the code has been written in.\"";

    private final int ISSUE_TYPE_CR = 0x080a000f;
    private final String ISSUE_NAME_CR = "ResponseHeaderInjection(CR)";
    private final String SEVERITY_CR = "Medium";
    private final String CONFIDENCE_CR = "Certain";
    private final String ISSUE_BACKGROUND_CR = "CR Response Injection works in any browser, exclude Firefox";

    private static final String CRLFHeader = "Molly-Verification-Header:";
    private static final Pattern CRLFPattern = Pattern.compile("\\n\\s*" + CRLFHeader);
    private static final Pattern CRPattern = Pattern.compile("\\r\\s*" + CRLFHeader);
    private static final List<String> CRLFSplitters = new ArrayList<>();

    public CRLFPlugin(IBurpExtenderCallbacks callbacks, BurpMollyPackConfig extConfig) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.flags = new HashSet<>();
        initCRLFSplitters();
    }

    public List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        IResponseInfo resp = helpers.analyzeResponse(baseRequestResponse.getResponse());
        IRequestInfo req = helpers.analyzeRequest(baseRequestResponse.getRequest());
        if (resp == null | req == null) return null;

        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        IHttpService httpService = baseRequestResponse.getHttpService();

        List<IScanIssue> issues = new ArrayList<>();


        if (!flags.contains(url.getProtocol() + url.getHost())) {
            IScanIssue res = scanRootDirectory(baseRequestResponse, insertionPoint);
            if (res != null) issues.add(res);
            flags.add(url.getProtocol() + url.getHost());
        }

        String uuid = UUID.randomUUID().toString().replaceAll("-", "");
        IHttpRequestResponse checkUUID = this.callbacks.makeHttpRequest(httpService, insertionPoint.buildRequest(this.helpers.stringToBytes(uuid)));
        if (checkUUID == null || checkUUID.getResponse() == null) return null;

        String respHeaders = String.join("\n", this.helpers.analyzeResponse(checkUUID.getResponse()).getHeaders());

        if (respHeaders.contains(uuid)) {
            for (String payload : CRLFSplitters) {
                String finalPayload = uuid.substring(0, 5) + payload + CRLFHeader + uuid.substring(6);
                IHttpRequestResponse attack = this.callbacks.makeHttpRequest(httpService,
                        insertionPoint.buildRequest(this.helpers.stringToBytes(finalPayload)));
                IScanIssue res = analyzeResponse(attack, insertionPoint, finalPayload);
                if (res != null) issues.add(res);
            }
        }

        if (issues.size() > 0) return issues;
        return null;
    }

    public IScanIssue analyzeResponse(IHttpRequestResponse attack, IScannerInsertionPoint insertionPoint, String finalPayload) {
        if (attack == null || attack.getResponse() == null) return null;

        String respAttackHeaders = String.join("\n", this.helpers.analyzeResponse(attack.getResponse()).getHeaders());
        Matcher crlfMatcher = CRLFPattern.matcher(respAttackHeaders);

        if (crlfMatcher.find()) {
            String body = helpers.bytesToString(attack.getResponse());
            List requestMarkers = new ArrayList(1);
            List responseMarkers = new ArrayList(1);
            requestMarkers.add(insertionPoint.getPayloadOffsets(this.helpers.stringToBytes(finalPayload)));
            responseMarkers.add(new int[]{body.indexOf(CRLFHeader), body.indexOf(CRLFHeader) + CRLFHeader.length()});

            String attackDetails = "Vulnerability detected at <b>" + insertionPoint.getInsertionPointName() + "</b>, " +
                    "payload was set to <b>" + this.helpers.urlEncode(finalPayload) + "</b><br/>" +
                    "Found response: " + crlfMatcher.group();

            return new CustomScanIssue(attack.getHttpService(),
                    this.helpers.analyzeRequest(attack).getUrl(),
                    new IHttpRequestResponse[]{this.callbacks.applyMarkers(attack, requestMarkers, responseMarkers)},
                    attackDetails, ISSUE_TYPE_CRLF, ISSUE_NAME_CRLF, SEVERITY_CRLF, CONFIDENCE_CRLF,
                    "", ISSUE_BACKGROUND_CRLF, "");
        }

        Matcher crMatcher = CRPattern.matcher(respAttackHeaders);

        if (crMatcher.find()) {
            String body = helpers.bytesToString(attack.getResponse());
            List requestMarkers = new ArrayList(1);
            List responseMarkers = new ArrayList(1);
            requestMarkers.add(insertionPoint.getPayloadOffsets(this.helpers.stringToBytes(finalPayload)));
            responseMarkers.add(new int[]{body.indexOf(CRLFHeader), body.indexOf(CRLFHeader) + CRLFHeader.length()});

            String attackDetails = "Vulnerability detected at <b>" + insertionPoint.getInsertionPointName() + "</b>, " +
                    "payload was set to <b>" + this.helpers.urlEncode(finalPayload) + "</b><br/>" +
                    "Found response: " + crMatcher.group();

            return new CustomScanIssue(attack.getHttpService(),
                    this.helpers.analyzeRequest(attack).getUrl(),
                    new IHttpRequestResponse[]{this.callbacks.applyMarkers(attack, requestMarkers, responseMarkers)},
                    attackDetails, ISSUE_TYPE_CR, ISSUE_NAME_CR, SEVERITY_CR, CONFIDENCE_CR,
                    "", ISSUE_BACKGROUND_CR, "");
        }

        return null;
    }

    public IScanIssue scanRootDirectory(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        IRequestInfo req = helpers.analyzeRequest(baseRequestResponse.getRequest());
        IHttpService httpService = baseRequestResponse.getHttpService();

        String uuid = UUID.randomUUID().toString().replaceAll("-", "");
        String uuidPayload = req.getMethod() + " /" + uuid + " HTTP/1.1";

        List<String> reqHeaders = req.getHeaders();
        reqHeaders.set(0, uuidPayload);
        byte[] body = helpers.stringToBytes(helpers.bytesToString(baseRequestResponse.getRequest()).substring(req.getBodyOffset()));
        byte[] modifiedReq = helpers.buildHttpMessage(reqHeaders, body);

        IHttpRequestResponse checkUUID = this.callbacks.makeHttpRequest(httpService, modifiedReq);
        if (checkUUID == null || checkUUID.getResponse() == null) return null;

        String respHeaders = String.join("\n", this.helpers.analyzeResponse(checkUUID.getResponse()).getHeaders());

        if (respHeaders.contains(uuid)) {
            for (String payload : CRLFSplitters) {
                String finalPayload = uuid.substring(0, 5) + payload + CRLFHeader + uuid.substring(6);
                String finalRequestUriBuilder = req.getMethod() + " /" + finalPayload + " HTTP/1.1";

                reqHeaders.set(0, finalRequestUriBuilder);
                body = helpers.stringToBytes(helpers.bytesToString(baseRequestResponse.getRequest()).substring(req.getBodyOffset()));
                modifiedReq = helpers.buildHttpMessage(reqHeaders, body);
                IHttpRequestResponse attack = this.callbacks.makeHttpRequest(httpService, modifiedReq);

                IScanIssue res = analyzeResponse(attack, insertionPoint, finalPayload);
                if (res != null) return res;
            }
        }
        return null;
    }

    private void initCRLFSplitters() {

        byte[] CDRIVES = new byte[]{(byte) 0xE5, (byte) 0x98, (byte) 0x8A, (byte) 0xE5, (byte) 0x98, (byte) 0x8D,};

        CRLFSplitters.add(helpers.bytesToString(CDRIVES));
        CRLFSplitters.add("\r");
        CRLFSplitters.add("\r ");
        CRLFSplitters.add("\r\t");
        CRLFSplitters.add("\r\n");
        CRLFSplitters.add("\r\n ");
        CRLFSplitters.add("\r\n\t");
        CRLFSplitters.add("\r\n\t");

        CRLFSplitters.add("%0d");
        CRLFSplitters.add("%0a");
        CRLFSplitters.add("%0d%0a");
        CRLFSplitters.add("%0d%0a%09");
        CRLFSplitters.add("%0d+");
        CRLFSplitters.add("%0d%20");
        CRLFSplitters.add("%0d%0a+");
        CRLFSplitters.add("%E5%98%8A%E5%98%8D");
        CRLFSplitters.add("%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D");

        CRLFSplitters.add("%c4%8d%c4%8a"); // https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2216

    }
}
