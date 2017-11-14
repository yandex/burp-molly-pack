package com.yandex.burp.extensions.plugins.audit;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;

import java.util.List;

/**
 * Created by a-abakumov on 16/02/2017.
 */
public interface IAuditPlugin {
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint);
}
