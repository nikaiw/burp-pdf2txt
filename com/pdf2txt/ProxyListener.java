package com.pdf2txt;

import burp.*;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.List;

public class ProxyListener implements IProxyListener, IHttpListener {
    IBurpExtenderCallbacks callback;

    public ProxyListener(IBurpExtenderCallbacks callbacks) {
        this.callback  = callbacks;
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if(!messageIsRequest){
            byte[] responsebyte = message.getMessageInfo().getResponse();
            IResponseInfo responseInfo = callback.getHelpers().analyzeResponse(responsebyte);
            byte[] body = Arrays.copyOfRange(responsebyte, responseInfo.getBodyOffset(), responsebyte.length);
            if(body.length > 4) {
                if (isPdfFile(body, 0)) {
                    String response = null;
                    try {
                        PdfParser parser = new PdfParser();
                        String pdftxt = parser.parse(body);
                        List<String> headers = responseInfo.getHeaders();
                        byte[] newresponse = callback.getHelpers().buildHttpMessage(headers, pdftxt.getBytes());
                        message.getMessageInfo().setResponse(newresponse);

                    } catch (IllegalAccessException e) {
                        e.printStackTrace();
                    } catch (InstantiationException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    public static boolean isPdfFile(byte[] respBytes, int bodyOffset) {
        return respBytes[bodyOffset] == (byte) '%' && //
                respBytes[bodyOffset+1] == (byte) 'P' && //
                respBytes[bodyOffset+2] == (byte) 'D' && //
                respBytes[bodyOffset+3] == (byte) 'F';
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if(!messageIsRequest){
            byte[] responsebyte = messageInfo.getResponse();
            IResponseInfo responseInfo = callback.getHelpers().analyzeResponse(responsebyte);
            byte[] body = Arrays.copyOfRange(responsebyte, responseInfo.getBodyOffset(), responsebyte.length);
            if(isPdfFile(body, 0)) {
                String response = null;
                try {
                    PdfParser parser = new PdfParser();
                    String pdftxt = parser.parse(body);
                    List<String> headers = responseInfo.getHeaders();
                    byte[] newresponse = callback.getHelpers().buildHttpMessage(headers, pdftxt.getBytes());
                    messageInfo.setResponse(newresponse);

                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                } catch (InstantiationException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
