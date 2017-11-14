package com.yandex.burp.extensions.plugins.grep;

import burp.IHttpRequestResponse;
import burp.IScanIssue;

/**
 * Created by ezaitov on 19.12.2016.
 */
public interface IGrepPlugin {

    IScanIssue grep(IHttpRequestResponse baseRequestResponse);

}
