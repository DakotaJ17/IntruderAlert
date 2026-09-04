I used PyCharm & Windows for this. It is currently detecting three things:
1. Ping of Death (Large ICMP Packets)
2. SYN Floods (DoS Attacks)
3. Unencrypted Protocols

It does NOT actively prevent, only detects.

Step 1: Open PyCharm or install at https://www.jetbrains.com/pycharm/download/download-thanks.html?platform=windows 

Step 2: Create a new project and go to the terminal (located at the bottom left of the project page)

Step 3: Insert the line from the "scapy" file

Step 4: Download the "ids.py" file from GitHub and insert it into the project in PyCharm

Step 5: Save the project file to your computer

Step 6: Make sure you have Npcap installed, https://npcap.com/dist/npcap-1.88.exe
        When installing, make sure to select "Install Npcap in WinPcap API-compatible Mode" 

Step 7: Run command prompt as administrator and run your script.
        Press "Ctrl + C" to stop running it.

ARP Spoofing Detection to be added soon!
