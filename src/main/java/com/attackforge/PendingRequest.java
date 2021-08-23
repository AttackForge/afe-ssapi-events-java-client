package com.attackforge;

import java.util.TimerTask;
import java.util.concurrent.CompletableFuture;

public class PendingRequest {
    public CompletableFuture<JsonRpcResponse> success = new CompletableFuture<>();
    public CompletableFuture<JsonRpcResponse> failure = new CompletableFuture<>();
    public TimerTask timeout = null;
}
