# Mitigation for HiveNightmare
aka SeriousSam, or now CVE-2021–36934 (exploit allowing you to read any registry hives as non-admin).

# What is this?
An zero day exploit for HiveNightmare, which allows you to retrieve all registry hives in Windows 10 as a non-administrator user.  For example, this includes hashes in SAM, which can be used to execute code as SYSTEM.

# Scope
Works on all supported versions of Windows 10, where System Protection is enabled (should be enabled by default in most configurations). 

# How does this work?
The permissions on key registry hives are set to allow all non-admin users to read the files by default, in most Windows 10 configurations.  This is an error.

