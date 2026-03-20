package burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GoogleApiKeyScan extends ParamScan {

    private static final Pattern API_KEY_PATTERN = Pattern.compile("AIza[0-9A-Za-z_-]{35}");
    private static final String GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/";

    private static final String INFO_DETAIL =
            "<p>A Google API key (<code>AIza...</code>) was found in the response. " +
            "If the Generative Language API is enabled on the same GCP project and the key is unrestricted, " +
            "it may grant access to Gemini endpoints.</p>" +
            "<p><b>Remediation:</b> Audit key restrictions under " +
            "<b>APIs &amp; Services &gt; Credentials</b> in the GCP Console.</p>";

    private static final String GEMINI_DETAIL_PREFIX =
            "<p>A Google API key was found and <b>verified to grant Gemini API access</b> " +
            "(CWE-1188, CWE-269). Unrestricted keys silently inherit access to Gemini " +
            "when the Generative Language API is enabled on the project.</p>";

    private static final String GEMINI_DATA_EXPOSURE =
            "<p><b>Impact:</b> An attacker may access uploaded files and cached context via " +
            "<code>/files/</code> and <code>/cachedContents/</code>, run up billing costs, " +
            "and exhaust API quotas.</p>";

    private static final String REMEDIATION =
            "<p><b>Remediation:</b> Rotate this key and restrict it to required APIs only under " +
            "<b>APIs &amp; Services &gt; Credentials</b>. Use separate GCP projects for " +
            "public-facing keys and sensitive APIs.</p>";

    private enum GeminiEndpoint {
        MODELS("models", "List models"),
        FILES("files", "Access uploaded files and datasets"),
        CACHED_CONTENTS("cachedContents", "Access cached context and documents");

        final String path;
        final String description;

        GeminiEndpoint(String path, String description) {
            this.path = path;
            this.description = description;
        }
    }

    private final ConcurrentHashMap<String, EnumSet<GeminiEndpoint>> verifiedKeys = new ConcurrentHashMap<>();

    GoogleApiKeyScan(String name) {
        super(name);
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse basePair) {
        byte[] responseBytes = basePair.getResponse();
        if (responseBytes == null) {
            return Collections.emptyList();
        }

        String response = Utilities.helpers.bytesToString(responseBytes);
        Set<String> uniqueKeys = extractUniqueKeys(response);
        if (uniqueKeys.isEmpty()) {
            return Collections.emptyList();
        }

        List<IScanIssue> issues = new ArrayList<>();
        IHttpService httpService = basePair.getHttpService();
        java.net.URL url = Utilities.helpers.analyzeRequest(basePair).getUrl();

        for (String apiKey : uniqueKeys) {
            IHttpRequestResponse markedPair = applyResponseMarker(basePair, response, apiKey);
            IHttpRequestResponse[] evidence = new IHttpRequestResponse[]{markedPair};
            String redactedKey = redactKey(apiKey);

            if (Utilities.unloaded.get()) {
                break;
            }

            EnumSet<GeminiEndpoint> accessible = getAccessibleEndpoints(apiKey);
            if (!accessible.isEmpty()) {
                boolean hasDataExposure = accessible.contains(GeminiEndpoint.FILES)
                        || accessible.contains(GeminiEndpoint.CACHED_CONTENTS);

                issues.add(new CustomScanIssue(
                        httpService, url, evidence,
                        hasDataExposure
                                ? "Google API Key with Gemini API Access (Data Exposure)"
                                : "Google API Key with Gemini API Access",
                        buildGeminiDetail(redactedKey, accessible, hasDataExposure),
                        "Certain",
                        hasDataExposure
                                ? CustomScanIssue.severity.High
                                : CustomScanIssue.severity.Medium
                ));
            } else {
                issues.add(new CustomScanIssue(
                        httpService, url, evidence,
                        "Google API Key Detected",
                        INFO_DETAIL + "<p>Key found: <code>" + redactedKey + "</code></p>",
                        "Certain", CustomScanIssue.severity.Information
                ));
            }
        }

        return issues;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint) {
        return Collections.emptyList();
    }

    private Set<String> extractUniqueKeys(String response) {
        Set<String> keys = new HashSet<>();
        Matcher matcher = API_KEY_PATTERN.matcher(response);
        while (matcher.find()) {
            keys.add(matcher.group());
        }
        return keys;
    }

    private EnumSet<GeminiEndpoint> getAccessibleEndpoints(String apiKey) {
        EnumSet<GeminiEndpoint> cached = verifiedKeys.get(apiKey);
        if (cached != null) {
            return cached;
        }
        EnumSet<GeminiEndpoint> result = probeAllEndpoints(apiKey);
        if (result != null) {
            verifiedKeys.put(apiKey, result);
        }
        return result != null ? result : EnumSet.noneOf(GeminiEndpoint.class);
    }

    private EnumSet<GeminiEndpoint> probeAllEndpoints(String apiKey) {
        EnumSet<GeminiEndpoint> accessible = EnumSet.noneOf(GeminiEndpoint.class);
        boolean receivedDefinitiveResponse = false;

        for (GeminiEndpoint endpoint : GeminiEndpoint.values()) {
            if (Utilities.unloaded.get()) {
                return null;
            }
            Boolean result = probeEndpoint(apiKey, endpoint);
            if (result == null) {
                continue;
            }
            receivedDefinitiveResponse = true;
            if (result) {
                accessible.add(endpoint);
            }
        }

        return receivedDefinitiveResponse ? accessible : null;
    }

    private Boolean probeEndpoint(String apiKey, GeminiEndpoint endpoint) {
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(
                    GEMINI_BASE + endpoint.path + "?key=" + apiKey);
            HttpRequestResponse response = Utilities.montoyaApi.http().sendRequest(request);
            if (response.response() == null) {
                return null;
            }
            return response.response().statusCode() == 200;
        } catch (Exception e) {
            Utilities.err("Failed to verify Gemini " + endpoint.path + " access: " + e.getMessage());
            return null;
        }
    }

    private String buildGeminiDetail(String redactedKey, EnumSet<GeminiEndpoint> accessible, boolean hasDataExposure) {
        StringBuilder detail = new StringBuilder();
        detail.append(GEMINI_DETAIL_PREFIX);

        detail.append("<p><b>Accessible endpoints:</b></p><ul>");
        for (GeminiEndpoint endpoint : accessible) {
            detail.append("<li><code>/v1beta/").append(endpoint.path)
                    .append("/</code> &mdash; ").append(endpoint.description).append("</li>");
        }
        detail.append("</ul>");

        if (hasDataExposure) {
            detail.append(GEMINI_DATA_EXPOSURE);
        }

        detail.append(REMEDIATION);
        detail.append("<p>Key found: <code>").append(redactedKey).append("</code></p>");
        return detail.toString();
    }

    private String redactKey(String apiKey) {
        return apiKey.substring(0, 8) + "..." + apiKey.substring(apiKey.length() - 4);
    }

    private IHttpRequestResponse applyResponseMarker(IHttpRequestResponse basePair, String response, String apiKey) {
        int keyStart = response.indexOf(apiKey);
        if (keyStart < 0) {
            return basePair;
        }
        List<int[]> responseMarkers = Collections.singletonList(
                new int[]{keyStart, keyStart + apiKey.length()}
        );
        return Utilities.callbacks.applyMarkers(basePair, null, responseMarkers);
    }
}
