# 

## Failures & tests that didnt work out.
- Rendering the XML was suprisngly complicated, had to update my config file that controls uploads to Splunk, Then extracting values from specific XML fields using regex provided another layer of complexity.
## Lessons learnt:
- Sigma rules have very limited functionality, use them more as a hypothesis & a backbone generator for other languages like KQL/ SPL.
- Correlating multiple data sources in Sigma isn't possible, it's better to generate multiple rules in one sigma file , then combine them in your chosen SIEM language post conversion. Or to utilize existing functionality in your detection envrionment eg. Microsoft Sentinel Fusion, UEBA or automatic correlation of alerts based upon entities involved.