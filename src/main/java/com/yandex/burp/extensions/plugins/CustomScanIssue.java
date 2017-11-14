package com.yandex.burp.extensions.plugins;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

import java.net.URL;

/**
 * Created by a-abakumov on 28/02/2017.
 */
public class CustomScanIssue implements IScanIssue {

    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String issueDetail;
    private int issueType;
    private String issueName;
    private String severity;
    private String confidence;
    private String remediationDetail;
    private String issueBackground;
    private String remediationBackground;


    public CustomScanIssue(IHttpService httpService,
                           URL url,
                           IHttpRequestResponse[] httpMessages,
                           String issueDetail,
                           int issueType,
                           String issueName,
                           String severity,
                           String confidence,
                           String remediationDetail,
                           String issueBackground,
                           String remediationBackground) {

        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.issueDetail = issueDetail;
        this.issueType = issueType;
        this.issueName = issueName;
        this.severity = severity;
        this.confidence = confidence;
        this.remediationDetail = remediationDetail;
        this.issueBackground = issueBackground;
        this.remediationBackground = remediationBackground;

    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return issueName;
    }

    @Override
    public int getIssueType() {
        return issueType;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return issueBackground;
    }

    @Override
    public String getRemediationBackground() {
        return remediationBackground;
    }

    @Override
    public String getIssueDetail() {
        return issueDetail;
    }

    @Override
    public String getRemediationDetail() {
        return remediationDetail;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
}
