+++
title = "OpenFraudMonitoring V1.4"
date = 2026-10-24
draft = false
tags = ["OpenFraudMonitoring", "threat-intel", "cybercrime", "dev"]
summary = "An overview of OpenFraudMonitoring V1.4, covering STIX compliance, OpenCTI enrichment, threat intelligence dissemination, and blocking malicious IP addresses."
+++

# OpenFraudMonitoring v1.4

## AI Disclaimer
This report was completely written by myself, a human.

## What's OFM?
See the [previous blogpost](https://blog.dreadfog.fr/posts/tlpclear_20261001_ofm_v1_2/) for an overview of the capabilities of the platform


## What's covered in this blog post
The goal of this blog post is to go over how OFM can be integrated into a Cyber Threat intelligence-oriented workflow. Notably

- OFM's compliance with the STIX2.1 format
- Enrichment with an external OpenCTI instance
- Threat Intelligence dissemination
- How to block malicious sessions identified through OFM?

## OFM's compliance with the STIX2.1 format
As OFM is (in a way) a Cyber Threat Intelligence platform, I wanted it to be compliant with the Cyber Threat Intelligence standard that is STIX.
- [Introduction to STIX](https://oasis-open.github.io/cti-documentation/stix/intro.html)
- [STIX2.1 standard](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html)

To do this, I implemented the standard as the founding block of OpenFraudMonitoring. All entities except sessions and devices are saved as STIX entities in OFM. This includes the observables (ip addresses, user agents, autonomous systems), the indicators, the relationships and the Threat Intelligence received from an external source (malware, campaign, intrusion set, etc...). Here is for example how an Autonomous system is modelled in OFM:
![](217c24fa-d972-4cd9-97e2-3e03680104d3.png)

By the way, you can see that I have included OpenCTI-specific fields for some metadata. This is because my **main objective with regards to integration is to make communication with an OpenCTI instance as seamless as possible**. 

## Enrichment with an external OpenCTI instance
If you are in the Cyber Threat Intelligence field, you have probably heard of [OpenCTI, an open source Threat Intelligence platform](https://github.com/opencti-platform/opencti).
This platform's main purpose is to centralize intelligence from various sources, and enable users to perform actions on / thanks to the data. I won't go deep into how this tool works, so please check out their repository for all the details.

The idea for OFM was simple: You may want to **use the intelligence you have to help you correctly identify malicious sessions on your infrastructure**. To do this, I have created an OpenCTI connector that gives you the possibility of looking up an IP address on a remote OpenCTI instance. This could give valuable information, like
- if this IP address is known for some malicious behavior
- if there is a precise attribution of the behavior
- if it is tied to a malicious campaign
- etc...

This is how it looks like in practice. Let's say that you have the knowledge in OpenCTI that an IP address is part of a botnet:
![](7a09481b-404d-40da-b6c8-3d44d996a3a5.png)
You can retrieve that information directly into the platform bby clicking on the "enrich" button (can also be configured to automatically lookup an IP address):
![](dad43c14-4adf-473e-a8cf-d43ed2c1f1fc.png)
Now, the information is visible in the intelligence view of the IP address:
![](445c50ed-ee74-4989-a264-94f52c1aa4e2.png)
You can also easily get this information in a pop-up when reviewing a session originating from this IP address:
![](8e26190f-6d4e-469c-94a1-82e86afd1097.png)

I plan on developing the possibility of configuring risk rules that can increase the score of a session if the IP address is known for malicious behavior. For now, it is simply indicative!

## Threat Intelligence dissemination
In Cyber Threat intelligence, we differentiate observables and indicators. Quoting from [OpenCTI's official documentation](https://filigran.io/blog/observables-indicators-and-infrastructure-in-cti),
- *Observables are raw data points or measurable events within a system or network. Observables on their own don’t necessarily indicate malicious behavior and can include items like legitimate IPs or domains associated with an organization.*
- *Indicators, or Indicators of Compromise (IOCs), are Observables enriched with context to signify potential threats. An Indicator typically includes a pattern or logic that defines the conditions in which an Observable might be a threat.*

In STIX, we say that "an indicator is based on an observable", which means that **the indicator is here to specify "we know malicious behavior tied to this specific observable"**.
Following this logic, OFM now has a new configuration parameter that gives the possibility of creating an indicator based on an IP address for which a session score went above a configurable threshold. This is to specify "this IP was at the origin of a malicious session, and we want to act upon it".
![](5c50730e-d8e3-4973-baea-bf9a6122be6b.png)

To act upon this information, OpenFraudMonitoring can expose Threat Intelligence feeds in two formats:
- A **TAXII feed**, that is the standard protocol for sending STIX-based information
- A **basic CSV feed** that is here to help integrate OFM more broadly directly with other tools.

Here is for example how a simple CSV feed can be configured to yield currently valid (unrevoked) indicators for detection / blocking:
![](4b8c9a23-0881-43dd-b56a-fad3c5ddbb39.png)

## How to block malicious sessions identified through OFM?
Thanks to the external CSV/TAXII feeds, **you can integrate OFM with firewalls, SIEMS, and basically any tool that is capable of ingesting raw IP lists, CSV feeds or TAXII feeds**.

For the sake of simplicity, and also because initially the goal of this project was to protect my NAS, I will show you how you can easily **block malicious IP addresses by simply using nftables**

In OFM's Github repo, I have added a [basic script](https://github.com/DreadFog/OpenFraudMonitoring/tree/main/docs/dissemination) that you can use, and that I will be demonstrating here
- configuration of the script with key variables
![](3cd36a9b-3e6d-4ac9-a3c0-1a00fa28f4eb.png)
- installation of the script, and configuration to periodically run it as root (cron)
![](a45ba37e-17cc-42f8-8d1c-9622a421c619.png)
- check of the correct execution through the logs
![](debf37ef-6f2c-4b26-9109-e602c6d11869.png)

And you can see that three IP addresses are currently blocked through NFTables, whose purpose is to simply drop the packets received by those IP addresses
![](140ecbe3-8638-44e9-a164-ef66feee7b7c.png)

## Outlook
This release give the possibility of easily blocking malicious IP addresses. After all, this is the purpose of OpenFraudMonitoring! Please reach out if you use OFM to block malicious IP addresses in another way (integration with Bunkerweb, Caddy configuration, etc...). This will help me improve the documentation on how to use OFM!
As always, you can check the repo here: [OpenFraudMonitoring](https://github.com/DreadFog/OpenFraudMonitoring)