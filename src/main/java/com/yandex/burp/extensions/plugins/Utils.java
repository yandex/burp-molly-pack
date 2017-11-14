package com.yandex.burp.extensions.plugins;

import burp.IResponseInfo;

import java.util.List;

/**
 * Created by a-abakumov on 24/03/2017.
 */
public class Utils {

    public static String getContentType(IResponseInfo resp) {
        String contentTypeValue = getHeaderValue(resp, "Content-Type");
        if (contentTypeValue != null) {
            return contentTypeValue.split(";", 2)[0].trim().toLowerCase();
        } else {
            return null;
        }
    }

    public static String getHeaderValue(IResponseInfo resp, String headerName) {
        for (String header : resp.getHeaders()) {
            String[] chunks = header.split(":", 2);

            if (chunks.length != 2 || !chunks[0].toLowerCase().equals(headerName.toLowerCase()))
                continue;

            return chunks[1].trim();
        }
        return null;
    }

    public static String getHeaderValue(List<String> headers, String headerName) {
        for (String header : headers) {
            String[] chunks = header.split(":", 2);

            if (chunks.length != 2 || !chunks[0].toLowerCase().equals(headerName.toLowerCase()))
                continue;

            return chunks[1].trim();
        }
        return null;
    }


}
