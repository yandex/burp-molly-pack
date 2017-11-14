package com.yandex.burp.extensions.plugins.audit;

import burp.*;
import com.yandex.burp.extensions.plugins.CustomScanIssue;
import com.yandex.burp.extensions.plugins.config.BurpMollyPackConfig;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static burp.IScannerInsertionPoint.INS_HEADER;

/**
 * Created by a-abakumov on 14/02/2017.
 */
public class HttPoxyPlugin implements IAuditPlugin {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private static final int ISSUE_TYPE = 0x080a0002;
    private static final String ISSUE_NAME = "Server-side proxy settings overwrite (HTTPoxy)";
    private static final String SEVERITY = "High";
    private static final String CONFIDENCE = "Certain";

    private static final String ISSUE_BACKGROUND =
            "HTTPoxy is a vulnerability that arises when the application reads the Proxy header value from an HTTP request," +
                    " saves it to the HTTP_PROXY environment variable, and outgoing HTTP requests made by the server use it to proxy those requests.<br><br>" +
                    "An attacker can use this behavior to redirect requests made by the application to a server under the attacker's control. " +
                    "They can also cause the server to initiate connections to hosts that are not directly accessible by the attacker, such as those on internal systems behind a firewall. " +
                    "For more information, refer to <a href=\"https://httpoxy.org\">HTTPoxy</a>.<br><br>";

    private static final String REMEDIATION_BACKGROUND =
            "The server should block the Proxy header in HTTP requests as it does not have any legitimate purpose. " +
                    "In most cases, updating the software used in the application stack should fix the issue.";


    public HttPoxyPlugin(IBurpExtenderCallbacks callbacks, BurpMollyPackConfig extConfig) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    public List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        if (insertionPoint.getInsertionPointType() != INS_HEADER) return null;

        IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        String payload = collaboratorContext.generatePayload(true);
        String httpPrefixedPayload = "Proxy: http://" + payload;
        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
        List<String> headers = requestInfo.getHeaders();

        headers.removeIf(header -> header != null && header.toLowerCase().startsWith("proxy:"));
        headers.add(httpPrefixedPayload);

        byte[] request = helpers.buildHttpMessage(headers, substring(baseRequestResponse.getRequest(), requestInfo.getBodyOffset()));
        IHttpRequestResponse scanCheckRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), request);

        List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(payload);
        if (collaboratorInteractions.isEmpty()) return null;

        List<IScanIssue> issues = new ArrayList<>();
        IScanIssue issue = reportIssue(httpPrefixedPayload, scanCheckRequestResponse, collaboratorInteractions.get(0));
        issues.add(issue);
        return issues;
    }

    private byte[] substring(byte[] array, int from) {
        int len = array.length - from;
        byte[] subArray = new byte[len];
        System.arraycopy(array, from, subArray, 0, len);
        return subArray;
    }

    private IScanIssue reportIssue(String payload, IHttpRequestResponse sentRequestResponse, IBurpCollaboratorInteraction collaboratorInteraction) {

        IHttpRequestResponse[] httpMessages = new IHttpRequestResponse[]{callbacks.applyMarkers(sentRequestResponse,
                buildRequestHighlights(payload, sentRequestResponse),
                Collections.emptyList())};
        String issueDetail = buildIssueDetail(payload, collaboratorInteraction);

        return new CustomScanIssue(sentRequestResponse.getHttpService(),
                helpers.analyzeRequest(sentRequestResponse).getUrl(),
                httpMessages, issueDetail,
                ISSUE_TYPE, ISSUE_NAME, SEVERITY, CONFIDENCE, "",
                ISSUE_BACKGROUND, REMEDIATION_BACKGROUND);
    }

    private List<int[]> buildRequestHighlights(String payload, IHttpRequestResponse sentRequestResponse) {

        List<int[]> requestHighlights = new ArrayList<>();

        int startOfPayload = helpers.indexOf(sentRequestResponse.getRequest(),
                helpers.stringToBytes(payload), true, 0,
                sentRequestResponse.getRequest().length);

        if (startOfPayload != -1) {
            requestHighlights.add(new int[]{startOfPayload, startOfPayload + payload.length()});
        }
        return requestHighlights;
    }

    private String buildIssueDetail(String payload, IBurpCollaboratorInteraction event) {
        return "The application is vulnerable to HTTPoxy attacks.<br><br>" +
                "The header <strong>" + payload + "</strong> was sent to the application.<br><br>" +
                "The application made " + eventDescription(event) + "<strong>" + event.getProperty("interaction_id") + "</strong>.<br><br>" +
                "The  " + interactionType(event.getProperty("type")) + " was received from the IP address " + event.getProperty("client_ip") +
                " at " + event.getProperty("time_stamp") + ".";
    }

    private String interactionType(String type) {
        if (type.equalsIgnoreCase("http")) {
            return "HTTP connection";
        } else if (type.equalsIgnoreCase("dns")) {
            return "DNS lookup";
        } else {
            return "interaction";
        }
    }

    private String eventDescription(IBurpCollaboratorInteraction event) {
        if (event.getProperty("type").equalsIgnoreCase("http")) {
            return "an <strong>HTTP</strong> request to the Collaborator server using the subdomain ";
        } else if (event.getProperty("type").equalsIgnoreCase("dns")) {
            return "a <strong>DNS</strong> lookup of type <strong>" + event.getProperty("query_type") + "</strong> to the Collaborator server subdomain ";
        } else {
            return "an unknown interaction with the Collaborator server using the subdomain ";
        }
    }

}
