# SysmonElevator

###Basic idea:
SysmonElevator is a WhiteBox Windows privilege escalation tool. The prerequisite is, that you are in possession of an Account with local administrative rights, in order to install the Sysmon driver. After a few days of Sysmon log history (or at least some hours in short assessments), you run the script, which will search the Sysmon log for processes that ran with administrative rights from an unsafe location (i.e. are writable by normal user accounts). It may turn out beneficial to carry out typical client self-management actions while testing. For example, requesting and installing software packets from software distribution. 

###Usage:
Open privileged powershell and set the execution policy to 'bypass'. Run SysmonElevator.ps1.


