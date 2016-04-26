# SysmonElevator

###Basic idea:
SysmonElevator is a WhiteBox Windows privilege escalation tool. As it uses the Sysmon log for the detection of vulnerable programs, the possession of an account with local administrative rights in order to install the Sysmon driver is a prerequisite. After a few days of Sysmon log history (or at least some hours in short assessments), you run the script, which will search the Sysmon log for processes that ran with administrative rights from an unsafe location (i.e. are writable by normal user accounts). 
It may turn out beneficial to carry out typical client self-management actions while testing. For example, requesting and installing software packets from software distribution. 

###Usage:
Open privileged powershell and set the execution policy to 'bypass'. Run SysmonElevator.ps1.
Additionally, the script parameter "-parseCommandLine" can be used. When enabled, also the CommandLine of all created processes in the Sysmon log will be evaluated. Sometimes it's possible that privileged processes run script files from writable locations.

