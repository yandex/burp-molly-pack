package com.yandex.burp.extensions.plugins.audit;

import burp.*;
import com.yandex.burp.extensions.plugins.CustomScanIssue;
import com.yandex.burp.extensions.plugins.config.BurpMollyPackConfig;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by a-abakumov on 25/02/2017.
 */
public class YaSSRFPlugin implements IAuditPlugin {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private static final List<String> SSRFPayloads = new ArrayList<>();

    private final int ISSUE_TYPE = 0x080a0007;
    private final String ISSUE_NAME_HTTP_INTERACTION = "SSRF Molly HTTP Interaction";
    private final String SEVERITY_HTTP_INTERACTION = "High";
    private final String CONFIDENCE_HTTP_INTERACTION = "Certain";

    private final String ISSUE_NAME_DNS_INTERACTION = "SSRF Molly DNS Interaction";
    private final String SEVERITY_DNS_INTERACTION = "Medium";
    private final String CONFIDENCE_DNS_INTERACTION = "Certain";

    public YaSSRFPlugin(IBurpExtenderCallbacks callbacks, BurpMollyPackConfig extConfig) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        initSSRFPayloads();
    }

    @Override
    public List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        IResponseInfo resp = helpers.analyzeResponse(baseRequestResponse.getResponse());
        IRequestInfo req = helpers.analyzeRequest(baseRequestResponse.getRequest());
        if (resp == null | req == null) return null;

        IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();

        List<IScanIssue> issues = new ArrayList<>();

        for (String payload : SSRFPayloads) {
            String collaboratorPayload = collaboratorContext.generatePayload(true);
            payload = payload.replace("{payloadUrl}", collaboratorPayload);
            IHttpRequestResponse attackRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),
                    insertionPoint.buildRequest(helpers.stringToBytes(payload)));
            List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(collaboratorPayload);

            if (!collaboratorInteractions.isEmpty()) {
                for (IBurpCollaboratorInteraction collaboratorInteraction : collaboratorInteractions) {
                    String type = collaboratorInteraction.getProperty("type");
                    if (type.equalsIgnoreCase("http")) {
                        String attackDetails = "The web server receives a URL <b> " + payload + " </b> " +
                                " at <b>" + insertionPoint.getInsertionPointName().toString() + " </b> or similar request from an upstream component and" +
                                " retrieves the contents of this URL, but it does not sufficiently ensure that the HTTP request is being" +
                                " sent to the expected destination.";
                        issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(),
                                helpers.analyzeRequest(attackRequestResponse).getUrl(),
                                new IHttpRequestResponse[]{callbacks.applyMarkers(attackRequestResponse, null, null)},
                                attackDetails, ISSUE_TYPE, ISSUE_NAME_HTTP_INTERACTION, SEVERITY_HTTP_INTERACTION, CONFIDENCE_HTTP_INTERACTION,
                                "", "", ""));
                    }
                    if (type.equalsIgnoreCase("dns")) {
                        String attackDetails = "The web server receives a URL <b> " + payload + " </b> " +
                                " at <b>" + insertionPoint.getInsertionPointName().toString() + " </b> " +
                                " and made DNS request. Please check for SSRF Vulnerability";
                        issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(),
                                helpers.analyzeRequest(attackRequestResponse).getUrl(),
                                new IHttpRequestResponse[]{callbacks.applyMarkers(attackRequestResponse, null, null)},
                                attackDetails, ISSUE_TYPE, ISSUE_NAME_DNS_INTERACTION, SEVERITY_DNS_INTERACTION, CONFIDENCE_DNS_INTERACTION,
                                "", "", ""));
                    }
                }
            }
        }

        List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchAllCollaboratorInteractions();
        if (!collaboratorInteractions.isEmpty()) {
            for (IBurpCollaboratorInteraction collaboratorInteraction : collaboratorInteractions) {
                String type = collaboratorInteraction.getProperty("type");
                if (type.equalsIgnoreCase("http")) {
                    String attackDetails = "The web server receives a URL at <b> " + insertionPoint.getInsertionPointName().toString() +
                            "</b> or similar request from an upstream component and" +
                            " retrieves the contents of this URL, but it does not sufficiently ensure that the HHTP request is being" +
                            " sent to the expected destination.";
                    issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, null)},
                            attackDetails, ISSUE_TYPE, ISSUE_NAME_HTTP_INTERACTION, SEVERITY_HTTP_INTERACTION, CONFIDENCE_HTTP_INTERACTION,
                            "", "", ""));
                }
                if (type.equalsIgnoreCase("dns")) {
                    String attackDetails = "The web server receives a URL at <b> " + insertionPoint.getInsertionPointName().toString() +
                            "</b> and made DNS request. Please check for SSRF Vulnerability";
                    issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, null)},
                            attackDetails, ISSUE_TYPE, ISSUE_NAME_DNS_INTERACTION, SEVERITY_DNS_INTERACTION, CONFIDENCE_DNS_INTERACTION,
                            "", "", ""));
                }
            }
        }
        return issues.isEmpty() ? null : issues;
    }

    public void initSSRFPayloads() {
        SSRFPayloads.add("{payloadUrl}");
        SSRFPayloads.add("http://{payloadUrl}");
        SSRFPayloads.add("https://{payloadUrl}");
        SSRFPayloads.add("https://{payloadUrl}/");
        SSRFPayloads.add("//{payloadUrl}");
        SSRFPayloads.add(".{payloadUrl}");
        SSRFPayloads.add("@{payloadUrl}");
        SSRFPayloads.add(":@{payloadUrl}");
    }
}
