Balbuzard - Documentation
=========================

This is the documentation home page for the Balbuzard tools. The online version is [here](https://bitbucket.org/decalage/balbuzard/wiki), and a copy can be found in the balbuzard/doc subfolder of the package.

[Balbuzard](http://www.decalage.info/python/balbuzard) is a package of malware analysis tools in python to extract patterns of interest from suspicious files (IP addresses, domain names, known file headers, interesting strings, etc). It can also crack malware obfuscation such as XOR, ROL, etc by bruteforcing and checking for those patterns.

## Balbuzard tools

- **[[balbuzard]]** is a tool to extract patterns of interest from malicious files, such as IP addresses, URLs, embedded files and typical malware strings. It is easily extensible with new  patterns, regular expressions and Yara rules.
- **[[bbcrack]]** uses a new algorithm based on patterns of interest to bruteforce typical malware obfuscation such as XOR, ROL, ADD and various combinations, in order to guess which algorithms/keys have been used. 
- **[[bbharvest]]** extracts all patterns of interest found when applying typical malware obfuscation transforms such as XOR, ROL, ADD and various combinations, trying all possible keys. It is especially useful when several keys or several transforms are used in a single file.
- **[[bbtrans]]** can apply any of the transforms from bbcrack (XOR, ROL, ADD and various combinations) to a file.

## When to use these tools

- If you need to analyze a new malicious file, you can first try **[[balbuzard]]** to extract strings/patterns of interest and detect embedded files in cleartext.
- Then if you think the malicious file might use an obfuscation algorithm such as XOR to hide interesting data (e.g. an embedded executable file), try **[[bbcrack]]** to find the algorithm and the key(s).
- Alternatively, if bbcrack is not successful, or if you think the file may use several algorithms and/or keys, try **[[bbharvest]]**. bbharvest is especially targeted at single strings obfuscated within an executable or malicious file.


## 5 minutes demo

See the **[[Demo]]** page to see examples and test the tools by yourself in a few minutes using the provided samples.

## Help wanted: 

- if you have malware samples or malicious documents with known obfuscation algorithms such as XOR, please [contact me](http://www.decalage.info/contact). That will help me a lot to improve bbcrack and bbharvest.
- if you know other strings, patterns, file headers useful for malware analysis that Balbuzard should support, or other obfuscation algorithms, please [contact me](http://www.decalage.info/contact).

## Documentation pages

- [[Home]]
- [[Demo]]
- [[Installation]]
- [[balbuzard]]
- [[bbcrack]]
- [[bbharvest]]
- [[bbtrans]]

## Quick links: 

- [Balbuzard home page](http://www.decalage.info/python/balbuzard)
- [Download](http://bitbucket.org/decalage/balbuzard/downloads) 
- [Documentation](https://bitbucket.org/decalage/balbuzard/wiki) 
- [Contact](http://www.decalage.info/contact) 
- [Report issues](https://bitbucket.org/decalage/balbuzard/issues?status=new&status=open) 
- [Updates on Twitter](https://twitter.com/decalage2)

See <http://www.decalage.info/python/balbuzard> for more info and other tools.


