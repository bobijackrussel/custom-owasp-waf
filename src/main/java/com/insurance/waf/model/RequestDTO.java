package com.insurance.waf.model;

public class RequestDTO {
	private String requestURI;
	private String method;
	private String source_ip;
	private String user_agent;
	private String payload;
	private String type;
	private String match_type;
	private String category;
	
	public String showRequestURI() { return requestURI; }
	public String showMethod() { return method; }
	public String showSourceIP() { return source_ip; }
	public String showUserAgent() {return user_agent; }
	public String showPayload() { return payload; }
	public String showType() { return type; }
	public String showMatchType() {return match_type; }
	public String showCategory() {return category; }
	
	public void setRequestURI(String s) { this.requestURI=s; }
	public void setMethod(String s) { this.method=s; }
	public void setSourceIP(String s) { this.source_ip=s; }
	public void setUserAgent(String s) { this.user_agent=s; }
	public void setPayload(String s) { this.payload=s; }
	public void setType(String s) { this.type=s; }
	public void setMatchType(String s) { this.match_type=s; }
	public void setCategory(String s) {this.category=s; }
}
