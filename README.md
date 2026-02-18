-:THREAT DETECTION:-
Login Audit & Threat Detection System

This Python-based utility performs automated security auditing on system access logs. It parses structured login data to identify anomalous patterns and potential security threats using time-windowed analysis and record profiling.

Core Capabilities:
The system identifies four primary threat vectors:

Brute Force Attacks: 
Identifies rapid, successive authentication failures targeting specific accounts or originating from specific IP addresses.

Distributed Credential Abuse: 
Detects a single source (IP) attempting to access multiple distinct user accounts, characteristic of credential stuffing.

Compromised Access: 
Flags instances where an account experiences multiple consecutive failures followed by a successful login within a short temporal window.

User Mobility Risk: 
Identifies accounts accessed from a high number of geographically disparate IP addresses (IP hopping) within a restricted timeframe.


Technical Implementation

Parsing and Validation:
Regex Engines: 
Uses the re module to strictly validate log entries against the format: YYYY-MM-DD HH:MM:SS, username, ipv4, status.

Duplicate Detection:
Employs hashing and set structures to filter redundant log entries and ensure data integrity.

Strict Typing:
Validates IP address octets (0-255) and timestamp integrity using the datetime module.

State Management & Analysis

Sliding Windows:
Utilizes collections.deque (double-ended queues) to maintain sliding time windows. This allows for efficient memory management when evaluating events against specific total_seconds thresholds.

Profiling:
Implements object-oriented dossier management for both SustainedAction (Location-based) and CompromisedAccess (User-based) profiles.

Usage
Execute the script via CLI with the target log file as the primary argument:

python audit_system.py <filename.txt|csv|log>


Configuration Parameters:

The system operates based on defined heuristic thresholds:

Brute Force: 4 attempts within 120 seconds.

Sustained Action: 5 failures and a >60% failure rate within 300 seconds.

Credential Abuse: 3 or more unique IDs from a single IP.

User Mobility: 3 or more unique IP locations for a single ID.

Output Generation

The program generates two outputs:

STDOUT:
A real-time summary of line compilation counts and immediate threat flags.

Audit Report: 
A persistent text file (FINAL_AUDIT_REPORT_...txt) containing granular dossiers for every flagged IP and user account, detailing total attempts and specific threat status.

Data Integrity Warnings

The system includes a manipulation check. If the ratio of valid logs to total lines falls below 50%, a high-extent manipulation alert is triggered, suggesting the source data may be corrupted or intentionally obfuscated.