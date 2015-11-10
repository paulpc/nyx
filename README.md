nyx
===

Threat Intelligence artifact distribution

The goal of this project is to facilitate distribution of Threat Intelligence artifacts to defensive systems and to enhance the value derrived from both open source and commercial tools. An example usage of this is described on: https://www.sans.org/reading-room/whitepapers/threats/automated-defense-threat-intelligence-augment-35692

Needless to say, this is an experimental project - use at your own risk. Proper Documentation pending - as of right now it was damn hard to write, it should be damn hard to use ;).

How to use this:

1. install dependencies from `requirements.txt`

1. Change the configuration file and put in your systems. You will need either CRITs or Soltra to get started. You will need to create a few things in order to get started:
    - Set up the maps of high versus medium criticality/confidence sets. 
    - If you are using CRITs, make sure your intel is properly classified. 
    - If you are using Soltra, you will need to set up the searches for high versus medium indicators. 

1. You will also need to set up some of the objects in the various systems:
    - reference sets in QRadar
    - Palo Alto object groups
    - moloch wise configuration
    - bro intel framework
    - web filter custom categories

1. Run it in a test environment, make sure nothing breaks. Take the time to measure how long it takes to run - it might be useful when you set up the crontab job. Figure out how to deploy your intel files for the systems that don't have an API - store them on apache, use a share, or rsync them.

1. Run it in production (after you've read all code to know exactly what it does - don't trust me)

1. ***Beer*** - you achieved Threat Intelligence distribution automation, are a pioneer in your industry, and probably made a horde of interns less useful.

The technologies currently coded for are: 
- IBM QRadar (https://github.com/ibm-security-intelligence/)
- Palo Alto Networks (https://live.paloaltonetworks.com/twzvq79624/attachments/twzvq79624/documentation_tkb/246/1/XML-API-6.0.pdf)
- CRITs (https://github.com/crits/crits)
- BRO IDS (https://www.bro.org/sphinx/frameworks/intel.html)
- Soltra Edge (https://soltra.com/)
- Moloch (https://github.com/aol/moloch/wiki/WISE)
