
1: Stage 1
Load Controls




New DynamoDB Table: compliance-evidence

Each item becomes evidence.

Examle

    
    {
      "evidence_id":"uuid",
    
      "framework":"NIST",
    
      "control":"DE.AE-03",
    
      "service":"AWS WAF",
    
      "status":"PASS",
    
      "observation":
    
      "AWS WAF blocked malicious requests.",
    
      "source":
    
      "waf-events",
    
      "generated":
    
      "2026-07-28T13:02:11Z"
    }

Another Table: compliance-findings

It should store as follows:

    {
        "finding_id":"uuid",
    
        "framework":"CIS",
    
        "severity":"Medium",
    
        "control":"3.3",
    
        "status":"Needs Review",
    
        "recommendation":
    
        "CloudTrail should be enabled."
    }


