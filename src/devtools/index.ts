import type { RawCaptureEvent } from "../shared/models";
import { nowId, parseQueryString, toHeaderMap } from "../shared/utils";

chrome.devtools.panels.create("KZero Passwordless SSO Tracer", "", "panel.html", () => {});

const tabId = chrome.devtools.inspectedWindow.tabId;

const sendEvent = (event: RawCaptureEvent): void => {
  chrome.runtime.sendMessage({
    type: "DEVTOOLS_NETWORK_EVENT",
    tabId,
    event
  });
};

chrome.devtools.network.onRequestFinished.addListener((request) => {
  request.getContent((content) => {
    const queryString = (request.request.queryString ?? []).map(
      (entry) => `${encodeURIComponent(entry.name)}=${encodeURIComponent(entry.value)}`
    );

    const event: RawCaptureEvent = {
      id: nowId(),
      tabId,
      source: "devtools-network",
      timestamp: request.startedDateTime ? Date.parse(request.startedDateTime) : Date.now(),
      url: request.request.url,
      method: request.request.method,
      statusCode: request.response.status,
      requestHeaders: toHeaderMap(request.request.headers),
      responseHeaders: toHeaderMap(request.response.headers),
      queryParams: parseQueryString(queryString.join("&")),
      postBody: request.request.postData?.text,
      responseBody: content,
      redirectUrl: request.response.redirectURL,
      timingMs: request.time,
      host: (() => {
        try {
          return new URL(request.request.url).host;
        } catch {
          return "";
        }
      })()
    };

    sendEvent(event);
  });
});
