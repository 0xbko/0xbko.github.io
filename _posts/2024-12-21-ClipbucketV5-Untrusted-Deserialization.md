---
title: Clipbucket-v5 Untrusted Deserilisation - CVE-2024-54135, CVE-2024-54136
date: 2024-12-21 23:00:00 +1100
categories: [CVE, PHP]
tags: [cve-2024-54135, cve-2024-54136, php, deserialization]    
---

## Summary
[ClipbucketV5](https://oxygenz.fr/en/clipbucketv5/) is a PHP based web application which provides video and image sharing platform.  
The ClipbucketV5 was vulnerable to PHP Untrusted Deserialisation, and an unauthenticated adversary was able to inject a malicious PHP serialised object and cause unexpected behaviours of the application.  
![clipbucketv5_screenshot](/assets/blog/clipbucketv5/clipbucketv5_screenshot.jpg)  

## Background 
As part of my vulnerability research, I looked for a specific type of vulnerability within public GitHub repositories.  
I took advantage of the GitHub search functionality and find interesting projects which used a function I targeted for my research.  
While the search results may contain a huge number of repositories, it could include old and/or abandoned projects. Thus, I ignored any of the repositories which did not have commits within a year.  
Clipbucketv5 is an open source project, and its repository is accessible in GitHub, [clipbucket-v5](https://github.com/MacWarrior/clipbucket-v5).
This repository clearly provids an instruction for vulnerability reporting in its secuirty policy. This made an entire vulnerability disclosure process much easier, and I decided to dive into this application.  

## CVE-2024-54135 
### Vulnerable Code
| | |
| --- | --- |
|Version|ClipBucket-v5 Version 2.0 to Version 5.5.1 Revision 199|
|Vulnerability|PHP Untrusted Deserialisation|
|Affected File|upload/photo_upload.php|
  
Affected version of ClipBucket-v5 application failed to sanitise user supplied input in a form of PHP serialised object. The application accepted PHP serialised objects via `collection` GET and `photoIDS` POST parameters.  

![](/assets/blog/clipbucketv5/photo_upload.png)

Provided inputs were passed to `decode_key` function, which was defined in `upload/includes/classes/photos.class.php`. This function did not validate user supplied inputs and no security mechanisms were implemented before calling `unserialize` function, thus if an adversary was able to inject malicious payloads through the mentioned parameters it would be possible to exploit `unserialize` function.  

![](/assets/blog/clipbucketv5/decode_key.png)  

### Proof of Concept
Due to how the application treated user supplied inputs, there were two (2) ways of delivering payloads, via GET request and POST request.  
In order to reach the `unserialize` and `decode_key` function to exploit this issue, several conditions had to be met:  

__GET Attack Vector__
- User must be authenticated (photo_upload.php line 8 `logincheck()`) 

__POST Attack Vector__
- `EnterInfo` POST parameter must be supplied (photo_upload.php line 15)
- Payload must not contain `,` (photo_upload.php line 18)
- Payload must not contain whitespace (photo_upload.php line 22)

User authentication could be easily obtained via self-registration feature of the application which was enabled by default, and so are the rest of the criteria since the payload must be base64 encoded as seen `decode_key` function's `base64_decode()` function.  

As a proof of concept, known gadget chains from the PHPGGC tool was used to generate a payload which was to delete arbitrary files from a target system. [PHPGGC](https://github.com/ambionics/phpggc) is a tool to generate a PHP exploit payload which utilises PHP `unserialize()` function, similar to Java ysoserial.   
Below command was used to generate a payload, aiming to delete a file `/tmp/toDelete.txt`.  
```bash
./phpggc Smarty/FD1 /tmp/toDelete.txt
```

PHPGGC tool generates a following payload:
```txt
O:24:"Smarty_Internal_Template":2:{s:6:"cached";O:22:"Smarty_Template_Cached":3:{s:7:"lock_id";s:17:"/tmp/toDelete.txt";s:9:"is_locked";b:1;s:7:"handler";O:34:"Smarty_Internal_CacheResource_File":0:{}}s:6:"smarty";O:6:"Smarty":4:{s:13:"cache_locking";i:1;s:9:"cache_dir";s:1:"/";s:12:"use_sub_dirs";b:1;s:5:"cache";b:1;}}
```
To exploit the vulnerability, the payload needed to be base64 encoded and supplied as a HTTP GET/POST parameter.  

The final HTTP request to exploit this issue is shown below:

![](/assets/blog/clipbucketv5/exploit_post.png)

The below screenshot shows the application trying to delete the mentioned file:

![](/assets/blog/clipbucketv5/file_delete.png)

## CVE-2024-54136
### Vulnerable Code
| | |
| --- | --- |
|Version|ClipBucket-v5 Version 5.5.1 Revision 199 and below|
|Vulnerability|PHP Untrusted Deserialisation|
|Affected File|upload/upload.php|

The version 5.5.1 had the same vulnerability as previous issue in `upload/upload.php`. It also accepted user supplied inputs via `collection` GET parameter:  
![](/assets/blog/clipbucketv5/upload.png)  
As seen in line 12, base64 encoded user supplied inputs via `collection` parameter were provided directly to `unserialize` function.

### Proof of Concept
Since the issue in this version was essentially same as previous vulnerability, same exploit worked.  
Instead, this time the endpoint was `upload.php` and the payload was provided via `collection` GET parameter: 
![](/assets/blog/clipbucketv5/exploit_get.png)

## Impact
If an adversary successfully exploited the above issues, it was possible to delete arbitrary files from the file system. An adversary could delete any of the application source files to make the application unusable, or if the application relies on a specific file to restrict access to installer an adversary could initiate application installation and create a new administrative user account. This essentially takes over the application.
Also, if an adversary can identify another gadget chain it would be possible to obtain remote code execution.  

## Timeline
|||
|---|---|
|2024/11/30|Initial vulnerability report via Email was sent|
|2024/12/03|Response from Oxygenz Team|
|2024/12/04|Draft GitHub Security Advisories were created|
|2024/12/05|GitHub issued CVE-2024-54135 and CVE-2024-54136|
|2024/12/06|GitHub Security Advisories were published|

Thanks [OXYGENZ](https://oxygenz.fr/en/) team for being responsive and collaborative throughout the process. 
