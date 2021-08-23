package com.attackforge;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import org.json.JSONException;
import org.json.JSONObject;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class App {
    private static Timer timer = new Timer();
    private static TimerTask heartbeatTimerTask = null;
    private static Map<String, CompletableFuture<JsonRpcResponse>> pendingRequests = new HashMap<>();

    private static void notification(String method, JSONObject params) {
        System.out.format("method: %s%n", method);

        if (params != null) {
            System.out.println("params:");
            System.out.println(params.toString(2));
        }

        /* ENTER YOUR INTEGRATION CODE HERE */
        /* method contains the event type e.g. vulnerability-created */
        /* params contains the event body e.g. JSON object with timestamp & vulnerability details */
    }

    public static void main(String[] args) {
        connect();
    }

    private static void connect() {
        if (System.getenv("HOSTNAME") == null) {
            System.out.println("Environment variable HOSTNAME is undefined");
            System.exit(1);
        }

        if (System.getenv("EVENTS") == null) {
            System.out.println("Environment variable EVENTS is undefined");
            System.exit(1);
        }

        if (System.getenv("X_SSAPI_KEY") == null) {
            System.out.println("Environment variable X_SSAPI_KEY is undefined");
            System.exit(1);
        }

        String port = "443";

        if (System.getenv("PORT") != null) {
            port = System.getenv("PORT");
        }

        WebSocket.Listener listener = new WebSocket.Listener() {
            private StringBuilder text = new StringBuilder();

            @Override
            public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
                System.out.println("Connection closed");

                timer.schedule(new TimerTask() {
                    @Override
                    public void run() {
                        connect();
                    }
                }, 1000);

                return null;
            }

            @Override
            public void onError(WebSocket webSocket, Throwable error) {
                System.out.println(error.getMessage());

                timer.schedule(new TimerTask() {
                    @Override
                    public void run() {
                        connect();
                    }
                }, 1000);
            }

            @Override
            public CompletionStage<?> onText(WebSocket webSocket,
                                             CharSequence message,
                                             boolean last) {
                text.append(message);

                if (last) {
                    processCompleteTextMessage(webSocket, text);
                    text = new StringBuilder();
                }

                webSocket.request(1);
                return null;
            }
        };

        try {
            System.out.print("Connecting...");

            /* Uncomment the following to trust self-signed certificated - perform at your own risk */
            //SSLContext sc = getVeryTrustingSSLContext();

            //if (sc == null) {
            //    System.out.println("Failed to created SSLContext");
            //    System.exit(1);
            //}

            //WebSocket ws = HttpClient.newBuilder()
            //        .sslContext(sc)
            //        .build()
            //        .newWebSocketBuilder()
            //        .header("X-SSAPI-KEY", System.getenv("X_SSAPI_KEY"))
            //        .buildAsync(new URI(String.format("wss://%s:%s/api/ss/events", System.getenv("HOSTNAME"), port)), listener)
            //        .get();

            /* Comment out the following to perform full certification validation */
            WebSocket ws = HttpClient.newHttpClient()
                    .newWebSocketBuilder()
                    .header("X-SSAPI-KEY", System.getenv("X_SSAPI_KEY"))
                    .buildAsync(new URI(String.format("wss://%s:%s/api/ss/events", System.getenv("HOSTNAME"), port)), listener)
                    .get();

            System.out.println("success");

            heartbeat(ws);
            subscribe(ws);
        }
        catch (Exception e) {
            System.out.println("failed");
            System.out.println(e.getMessage());

            timer.schedule(new TimerTask() {
                @Override
                public void run() {
                    connect();
                }
            }, 1000);
        }
    }

    private static SSLContext getVeryTrustingSSLContext() {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }
                public void checkServerTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                }
            }
        };

        // Install the all-trusting trust manager
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());

            return sc;
        }
        catch (Exception e) {
            return null;
        }
    }

    private static void heartbeat(WebSocket webSocket) {
        if (heartbeatTimerTask != null) {
            heartbeatTimerTask.cancel();
        }

        heartbeatTimerTask = new TimerTask() {
            @Override
            public void run() {
                System.out.println("Heartbeat not received");

                try {
                    webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "").join();
                    webSocket.abort();
                }
                catch (Exception e) {
                }

                connect();
            }
        };

        timer.schedule(heartbeatTimerTask, 30000 + 1000);
    }

    private static String loadReplayTimestamp() {
        String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

        try (BufferedReader reader = new BufferedReader(new FileReader(".replay_timestamp"))) {
            String input = reader.readLine();

            if (input.length() == 24) {
               timestamp = input;
               System.out.format("Loaded replay timestamp from storage: %s%n", timestamp);
            }
            else {
               System.out.println("Invalid timestamp stored in \".replay_timestamp\"");
            }
        }
        catch (IOException e) {
            if (System.getenv("FROM") != null) {
                timestamp = System.getenv("FROM");
                System.out.format("Loaded replay timestamp from environment: %s%n", timestamp);
            }
        }

        return timestamp;
    }

    private static void processCompleteTextMessage(WebSocket webSocket, StringBuilder text) {
        try {
            JSONObject payload = new JSONObject(text.toString());

            if (payload.optString("jsonrpc").equals("2.0")) {
                if (payload.has("method") && !payload.has("id")) {
                    JSONObject params = payload.optJSONObject("params");

                    if (params != null && params.has("timestamp")) {
                        storeReplayTimestamp(params.getString("timestamp"));
                    }

                    notification(payload.getString("method"), params);
                }
                else if (payload.has("method") && payload.has("id")) {
                    if (payload.getString("method").equals("heartbeat")) {
                        JSONObject response = new JSONObject();
                        response.put("jsonrpc", "2.0");
                        response.put("result", ZonedDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
                        response.put("id", payload.getString("id"));

                        webSocket.sendText(response.toString(), true);

                        heartbeat(webSocket);
                    }
                }
                else if (payload.has("result") && payload.has("id")) {
                    JsonRpcResponse response = new JsonRpcResponse();

                    response.id = payload.optString("id");
                    response.result = new JsonArrayObject(payload.optJSONObject("result"), payload.optJSONArray("result"));

                    if (pendingRequests.containsKey(response.id)) {
                        pendingRequests.get(response.id).complete(response);
                    }
                }
                else if (payload.has("error") && payload.has("id")) {
                    JsonRpcResponse response = new JsonRpcResponse();
                    response.id = payload.optString("id");
                    response.error = payload.optJSONObject("error");

                    if (pendingRequests.containsKey(response.id)) {
                        pendingRequests.get(response.id).complete(response);
                    }
                }
            }
        }
        catch (JSONException e) {
            System.out.println("error parsing message");
            System.out.println(e);
        }
    }

    private static void storeReplayTimestamp(String timestamp) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(".replay_timestamp"))) {
            writer.write(timestamp, 0, 24);
        }
        catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    private static void subscribe(WebSocket webSocket) throws ExecutionException, InterruptedException {
        List<String> events = Arrays.stream(System.getenv("EVENTS").split(",")).map(element -> element.trim()).collect(Collectors.toList());

        JSONObject params = new JSONObject();
        params.put("events", events);
        params.put("from", loadReplayTimestamp());

        String requestId = UUID.randomUUID().toString();

        JSONObject request = new JSONObject();
        request.put("jsonrpc", "2.0");
        request.put("method", "subscribe");
        request.put("params", params);
        request.put("id", requestId);

        CompletableFuture<JsonRpcResponse> responseFuture = new CompletableFuture<>();
        CompletableFuture<Void> timeoutFuture = new CompletableFuture<>();

        TimerTask timeout = new TimerTask() {
            @Override
            public void run() {
                timeoutFuture.complete(null);
            }
        };

        timer.schedule(timeout, 5000);

        pendingRequests.put(requestId, responseFuture);

        webSocket.sendText(request.toString(), true);

        CompletableFuture<?> combinedFuture = CompletableFuture.anyOf(responseFuture, timeoutFuture);
        combinedFuture.get();

        if (responseFuture.isDone()) {
            JsonRpcResponse response = responseFuture.get();

            if (response.result != null) {
                if (response.result.array != null) {
                    System.out.format("Subscribed to the following events: %s%n", response.result.array);
                    pendingRequests.remove(requestId);
                }
                else {
                    System.out.format("Subscription request %s failed with unexpected response - exiting%n");
                    pendingRequests.remove(requestId);
                    System.exit(1);
                }
            }
            else if (response.error != null) {
                System.out.format("Subscription request %s failed - exiting%n");
                System.out.println(response.error.toString(2));

                pendingRequests.remove(requestId);
                System.exit(1);
            }


        }
        else if (timeoutFuture.isDone()) {
            System.out.format("Subscription request %s timed out - exiting%n", requestId);
            pendingRequests.remove(requestId);
            System.exit(1);
        }
    }
}