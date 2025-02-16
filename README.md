# wpa-sec.stanev-Submit
Optimizes and automates submission of pcapng files to wpa-sec-stanev

I use AngryOxide (https://github.com/Ragnt/AngryOxide) to capture handshakes, etc.  I suggest you do this, too.  And, since I noticed that I would often capture the same SSIDs/BSSIDs and networks I ended up inadvertantly submitting the same work over and over.  Wasting my time and the wpa-sec cracks.   Make sure you edit the script and add your API KEY before using.  Also, check the requirements.txt.

Simply put, this script: 

Evaluates your pcapng before submitting.  Logs networks that have already been submitted with submitted.txt and doesn't submit those.  It will strip out submitted networks and submit unsubmitted networks should you get a pcapng file with mixed (submitted and new).  It gives a little report and also has a debug mode.  There are other improvements to be done, but this is good enough for me. 

You can download all of your cracked hashes from wpa-sec and then add the bssids (first field in the file) to submitted.txt so you don't submit those either. Assuming your download file is CRACKED.txt

cut -d':' -f1 CRACKED.txt >> submitted.txt

You can use findcrackednetworks.sh to find some around you that are already cracked, too. 
