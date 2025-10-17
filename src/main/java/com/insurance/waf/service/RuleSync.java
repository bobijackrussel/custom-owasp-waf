package com.insurance.waf.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class RuleSync {
	/*
	public static List<Rules> syncRule()
	{
		List<String> urls = List.of(
				//"https://raw.githubusercontent.com/coreruleset/coreruleset/b3722fc3f7e3213402f2495eb7c33a186cb937b5/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
				"https://raw.githubusercontent.com/coreruleset/coreruleset/b3722fc3f7e3213402f2495eb7c33a186cb937b5/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf"
				//"https://raw.githubusercontent.com/coreruleset/coreruleset/b3722fc3f7e3213402f2495eb7c33a186cb937b5/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf"
			);
		List<Rules> rules=new ArrayList<>();
		for(String url : urls)
		{
			try
			{
				rules.addAll(fetchAndParseRules(url));

			}
			catch(Exception e)
			{
				System.err.println("Error");
			}
		}
		return rules;
	}
	public static List<Rules> fetchAndParseRules(String url) throws IOException
	{
		List<Rules> arr = new ArrayList<>();
		
		URL fileurl = new URL(url);
		BufferedReader reader = new BufferedReader(new InputStreamReader(fileurl.openStream()));
		String line;
		while ((line = reader.readLine()) != null) 
		{
		    if (line.startsWith("SecRule")) 
		    {
		        Rules rule = parseLine(line);
		        if (rule != null) 
		        {
		            arr.add(rule);
		        }
		    }
		}
		return arr;
	}
	public static Rules parseLine(String line)
	{
		try
		{
			Pattern pattern = Pattern.compile("SecRule.*?\"(.*?)\".*?msg:'(.*?)'.*?severity:'(.*?)'");
			Matcher matcher = pattern.matcher(line);
			
			if(matcher.find())
			{
				String regex = matcher.group(1);
				String desc = matcher.group(2);
				String severe = matcher.group(3);
				
				Rules rule = new Rules();
				rule.putPattern(regex);
				rule.putDescription(desc.toLowerCase());
				//rule.putSeverity(severe);
				rule.putCategory("SQLi or XSS");
				rule.putTime(LocalDateTime.now());
				rule.putEnable(true);
				rule.putMatchType("Regex");
				rule.putType("Payload");
				
				return rule;
				
			}
		}
		catch (Exception e)
		{
			System.err.println("Error in RuleSync");
		}
		
		return null;
	}

	 */
}
