package com.insurance.waf.model;

import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
public class UnsecureRequest {
    private UUID uuid;
    private String request_uri;
    private String method;
    private String source_ip;
    private String useragent;
    private String payload;
    private UUID rule_matched;
    private boolean blocked;
    private LocalDateTime timestamp;
}
