import sys
import re
from collections import deque as dq
from datetime import datetime as dt

# ==================================================================================
# ------------------------ PARSING LINE FOR VALID RECORDS --------------------------
# ==================================================================================
class Validation:
    """
    Docstring for ParsingLine
    
    :var address: This class provides methods for effective duplicate detection,
                  and checking whether the line follows the format strictly or not.
    """
    def __init__(self):
        """
        Docstring for __init__
        
        :param self: INITIALIZING THE INPUT
        """
        self.seen = set()
    
    def validate(self, line)->tuple[bool, tuple]:
        if not line or not isinstance(line, str):
            return False, ()
        
        try:
            valid=re.fullmatch(r"^(\d{4}-\d{2}-\d{2} \d{1,2}:\d{1,2}:\d{1,2})\s*,\s*([a-z0-9_]{5,50})\s*,\s*((?:\d{1,3}\.){3}\d{1,3})\s*,\s*(success|fail)$", line, re.IGNORECASE)
            self.dt_stamp=valid.group(1).strip()
            self.username=valid.group(2).strip()
            self.location=valid.group(3).strip()
            self.status=valid.group(4).strip().lower()

            valid_log=self.is_valid()
            if valid_log:
                if self.is_duplicate():
                    return False, ()

                return True, (self.dt_stamp, self.username, self.location, self.status)
            
            return False, ()
        
        except (ValueError, TypeError, AttributeError):
            return False, ()
        
        except EOFError:
            sys.exit("[?] System's alert: Something went wrong.")


    def is_duplicate(self) -> bool:
        """
        Docstring for is_duplicate
        
        :param self: Checking if there is duplicate log entry
        :return: True if the string or logged entry is duplicate of previously logged entry
        :rtype: bool
        """
        record = (
            self.dt_stamp.strip(),
            self.username.strip(),
            self.location.strip(),
            self.status.strip().lower()
        )

        h = hash(record)

        if h in self.seen:
            return True
        
        self.seen.add(h)
        return False
    
    def is_valid(self)->bool:
        """
        Docstring for is_valid
        
        :param self: VALIDATING THE FORMAT
        :return: True if logged entry is in valid format
        :rtype: bool
        """
        # =============== date-time format ===============
        try:
            if not dt.strptime(self.dt_stamp, "%Y-%m-%d %H:%M:%S"): return False
        except ValueError:
            return False

        # =============== username format ================
        if not re.fullmatch(r"([a-z0-9_]{5,50})", self.username): return False

        # =============== location format ================
        if not all([0<=int(num)<=255 for num in self.location.split(".")]): return False

        # =============== status format ==================
        if not self.status.lower().strip() in ["success", "fail"]: return False

        # =============== final validated return ===================
        return True


# ==================================================================================
# ------------------- SUSTAINED ACTIONS AND LOCATION PROFILING ---------------------
# ==================================================================================
class SustainedAction:
    """
    Docstring for SustainedAction
    
    :var address: This class provides methods to help in
                  creation of the dictionary for sustained_action function.
    """
    def __init__(self):
        self.location_profile={}
    
    # ======================= ADDING LOCATION AS KEY ===========================
    def record_address(self, ipv: str)->None:
        if not ipv in self.location_profile.keys():
            self.location_profile[ipv]=self.record_dossier()
            
    # ==================== ADDING VALUES TO KEY (LOCATION) ========================
    def record_dossier(self)->dict:
        dossier = {
            "Total Users" : set(),
            "Brute Force Detected" : False,
            "Distributed Credential Abuse" : False,
            "Sustained Action Detected" : False,
            "Total Attempts Recorded" : 0,
            "Successful Attempts Recorded" : 0,
            "Failed Attempts Recorded" : 0,
        }
        return dossier
    
    # ====================== UPDATE TO EVERY LOCATION VALUES =======================
    def dossier_update(self, ipv: str, user: str, status: str)->None:
        self.location_profile[ipv]["Total Users"].add(user)
        self.location_profile[ipv]["Total Attempts Recorded"]+=1
        if status=="fail":
            self.location_profile[ipv]["Failed Attempts Recorded"]+=1
        else:
            self.location_profile[ipv]["Successful Attempts Recorded"]+=1
    # ====================== BRUTE FORCE DETECTION ================================
    def bruteforce_detected(self, ipv: str)->None:
        self.location_profile[ipv]["Brute Force Detected"]=True

    # ===================== SUSPICION FOR DISTRIBUTED ABUSE ========================
    def dca_detected(self, ipv: str)->None:
        self.location_profile[ipv]["Distributed Credential Abuse"]=True

    # ===================== SUSTAINED ACTION DETECTION =============================
    def threat_found(self, ipv: str)->None:
        self.location_profile[ipv]["Sustained Action Detected"]=True
    
    # ================= RETURNING THE MASTER DICTIONARY AS PROFILE =================
    def commence(self)->dict:
        return self.location_profile

# ==================================================================================
# ------------------- COMPROMISED ACCESS AND ACCOUNTS PROFILING --------------------
# ==================================================================================
class CompromisedAccess:
    """
    Docstring for CompromisedAccess
    
    :var address: This class provides methods to help in
                  creation of the dictionary for compromised_access function.
    """
    def __init__(self):
        self.account_profile={}
    
    def record_dossier(self)->dict:
        dossier = {
            "Total Locations" : set(),
            "Brute Force Detected" : False,
            "User mobility" : False,
            "Compromised Access Detected" : False,
            "Total Attempts Recorded" : 0,
            "Successful Attempts Recorded" : 0,
            "Failed Attempts Recorded" : 0,
        }
        return dossier
    # ====================== ADDING ACCOUNT AS KEY ===========================

    def record_address(self, id: str)->None:
        if not id in self.account_profile.keys():
            self.account_profile[id]=self.record_dossier()

    # ==================== ADDING VALUES TO KEY (ACCOUNT) ========================    
    def dossier_update(self, id: str, ipv: str, status: str)->None:
        self.account_profile[id]["Total Locations"].add(ipv)
        self.account_profile[id]["Total Attempts Recorded"]+=1
        if status=="fail":
            self.account_profile[id]["Failed Attempts Recorded"]+=1
        else:
            self.account_profile[id]["Successful Attempts Recorded"]+=1

    # ====================== BRUTE FORCE DETECTION ================================   
    def bruteforce_detected(self, id: str)->None:
        self.account_profile[id]["Brute Force Detected"]=True

    # ===================== SUSPICION FOR USER MOBILITY ============================
    def umr_detected(self, id: str)->None:
        self.account_profile[id]["User mobility"]=True

    # ===================== COMPROMISED ACCESS DETECTION ===========================
    def threat_found(self, id: str)->None:
        self.account_profile[id]["Compromised Access Detected"]=True
    
    # ================= RETURNING THE MASTER DICTIONARY AS PROFILE =================
    def commence(self)->dict:
        return self.account_profile


# =============================== THREAT DETECTION ===========================
def threat_analysis(r: list) -> tuple [list, list]:
    """
    Docstring for threat_analysis
    
    :param r: valid line recorded in main parsing function.
    :type r: list
    :return: two sets with all bruteforce locations and bruteforce accounts separately and two dictionaries of profiles, of .
    :rtype: tuple [set, set, dict, dict]
    """

    # ======================== Parameters for threat detection ========================
    parameter={
        "brute_force_attempts" : 4,
        "brute_force_time_frame" : 120,
        "threat_time_frame" : 300,
        "sustained_action_fails" : 5,
        "percentage_failed" : 0.6, # For 60% fails
        "distributed_abuse_ids" : 3,
        "compromised_access_fails" : 3,
        "user_mobility_locations" : 3
    }

    address_record=SustainedAction()
    """
    address record has been maintained as:
    {
    ip address : {
                    "Total Users" : set(),
                    "Distributed Credential Abuse" : False,
                    "Sustained Action Detected" : False,
                    "Total Attempts Recorded" : 0,
                    "Successful Attempts Recorded" : 0,
                    "Failed Attempts Recorded" : 0,
                },
    // same for next location
    }
    """

    account_record=CompromisedAccess()
    """
    account record has been maintained as:
    {
    username : {
                    "Total Locations" : set(),
                    "User mobilit" : False,
                    "Compromised Access Detected" : False,
                    "Total Attempts Recorded" : 0,
                    "Successful Attempts Recorded" : 0,
                    "Failed Attempts Recorded" : 0,
                },
    // same for next username
    }
    """
    # ====================== RESULTING SETS =========================
    bruteforce_users=set()
    bruteforce_ipv4s=set()
    sustained_ipv4s=set()
    compromised_users=set()
    dca_ipv4s=set()
    um_users=set()

    # ====================== DEQUE WINDOWS ==========================
    id_windows={} # time window for accounts with brute force detection
    ip_windows={} # time window for locations with brute force detection
    sa_windows={} # time window for locations with sustained actions and distributed credential abuse detection
    ca_windows={} # time window for accounts with compromised access and user mobility risk detection

    # ====================== ANALYSIS BGINS ===========================
    records=r
    for dt_stamp, user, ipv4, status in records:
        current=dt.strptime(dt_stamp, "%Y-%m-%d %H:%M:%S")

        # ===================== DOSSIER UPDATES ==================================
        address_record.record_address(ipv4)
        address_record.dossier_update(ipv4, user, status)
        
        account_record.record_address(user)
        account_record.dossier_update(user, ipv4, status)

        # ====================== BRUTE FORCE USERS ===========================
        user_dq = id_windows.setdefault(user, dq())
        user_dq.append((current, status.lower()))

        while user_dq and (current-user_dq[0][0]).total_seconds() > parameter["brute_force_time_frame"]:
            user_dq.popleft()
        
        bf_id_fail=0
        for _, st in user_dq:
            if st=="fail":
                bf_id_fail+=1
        
        if bf_id_fail>=parameter["brute_force_attempts"]:
            bruteforce_users.add(user)

        # ====================== BRUTE FORCE ADDRESSES ===========================
        ipv_dq = ip_windows.setdefault(ipv4, dq())
        ipv_dq.append((current, status.lower()))

        while ipv_dq and (current-ipv_dq[0][0]).total_seconds() > parameter["brute_force_time_frame"]:
            ipv_dq.popleft()
        
        bf_ip_fail=0
        for _, st in ipv_dq:
            if st=="fail":
                bf_ip_fail+=1
        
        if bf_ip_fail>=parameter["brute_force_attempts"]:
            bruteforce_ipv4s.add(ipv4)
    
        # ====================== SUSTAINED ACTION DETECTION =========================
        if not ipv4 in sa_windows:
            sa_windows[ipv4]=dq()
        
        sa_window=sa_windows[ipv4]
        sa_window.append((current, user, status))

        while sa_window and (current-sa_window[0][0]).total_seconds() > parameter["threat_time_frame"]:
            sa_window.popleft()
        
        # ====================== DETECTING THREATS =========================
        sa_fails=0
        sa_totals=0
        users=set()
        for _, id, st in sa_window:
            sa_totals+=1
            if st=="fail":
                sa_fails+=1
            users.add(id)
        
        # ====================== THREAT CONFIRMATION ========================
    
        if ipv4 in bruteforce_ipv4s:
            address_record.bruteforce_detected(ipv4)

        if len(users)>=parameter["distributed_abuse_ids"]:
            address_record.dca_detected(ipv4)
            dca_ipv4s.add(ipv4)

        if sa_fails>=parameter["sustained_action_fails"]:
            result = sa_fails/sa_totals

            if result>=parameter["percentage_failed"]:
                address_record.threat_found(ipv4)
                sustained_ipv4s.add(ipv4)

        # ====================== COMPROMISED ACCESS DETECTION =========================
        if not user in ca_windows:
            ca_windows[user]=dq()
        
        ca_window=ca_windows[user]
        ca_window.append((current, ipv4, status))

        while ca_window and (current-ca_window[0][0]).total_seconds() > parameter["threat_time_frame"]:
            ca_window.popleft()
        
        # ====================== DETECTING THREATS =========================
        ca_fails=0
        locations=set()
        for _, ip, st in ca_window:
            locations.add(ip)

            # ====================== THREAT CONFIRMATION ========================
            if st=="fail": ca_fails+=1
            if st=="success":
                if ca_fails>=parameter["compromised_access_fails"]:
                    account_record.threat_found(user)
                    compromised_users.add(user)
            
            if len(locations)>=parameter["user_mobility_locations"]:
                account_record.umr_detected(user)
                um_users.add(user)
        
        if user in bruteforce_users:
            account_record.bruteforce_detected(user)
    
    # ================ FINALIZING THE MASTER DICTIONARY AS PROFILE =================
    address_profiles = address_record.commence()
    account_profiles = account_record.commence()

    threat_records=[bruteforce_users, bruteforce_ipv4s, sustained_ipv4s, dca_ipv4s, compromised_users, um_users]
    profiles=[address_profiles, account_profiles]

    return threat_records, profiles


# ============================ TERMINAL REPORT DISPLAY =============================

def display(bf: tuple, sa: set, ca: set, dca: set, um: set, ipvs: dict, accounts: dict)->None:
    """
    Docstring for display
    
    :param bf: BRUTE FORCE RECORDS [IP ADDRESSES, USERNAMES]
    :type bf: tuple
    :param sa: SUSTAINED ATTACKS LOCATION RECORDS
    :type sa: dict
    :param ca: COMPROMISED ACCESS ACCOUNTS RECORDS
    :type ca: dict
    :param dca: DISTRIBUTED CREDENTIAL ABUSE LOCATION RECORDS
    :type dca: set
    :param um: USER MOBILITY ACCOUNTS RECORDS
    :type um: set
    """

    # Unzipping the entire details for final display or records over terminal window
    # ==============================================================================
    # ========================== BRUTE FORCE REPORTS ===============================
    bruteforce_users, bruteforce_ipv4s = bf

    # ========================== FINAL REPORT PRINTING =============================
    print("\n" + "="*80)
    print("="*80)
    print("            -: FINAL DISPLAY OF LOGIN REPORTS, FLAGS AND THREATS :-")
    
    # =========================== BRUTE FORCE REPORTING ============================
    print("\nBRUTE FORCE REPORTS:")
    
    # ============================ USER BRUTE FORCE DISPLAY ========================
    if bruteforce_users:
        print("\nAccounts detected with Brute force:")
        count = 1
        for user in sorted(bruteforce_users):
            print(f"{count}. {user}")
            count += 1
    else:
        print("\nAccounts detected with Brute force: None")
    
    # =========================== LOCATION BRUTE FORCE DISPLAY =====================
    if bruteforce_ipv4s:
        print("\nLocations detected with Brute force:")
        count = 1
        for ipv in sorted(bruteforce_ipv4s):
            print(f"{count}. {ipv}")
            count += 1
    else:
        print("\nLocations detected with Brute force: None")
    
    print("\n" + "-"*80)
    
    # ============================ SUSTAINED ACTIONS REPORTING =====================
    print("\nSUSTAINED ACTIONS RECORDED:")
    
    if sa:
        print("\nLocations recorded with Sustained Actions:")
        for count, location in enumerate(sa):
            print(f"{count}. {location}")
    else:
        print("\nLocations recorded with Sustained Actions: None")
    
    print("\n" + "-"*80)
    
    # ========================= COMPROMISED ACCESS REPORTING =======================
    print("\nCOMPROMISED ACCESS RECORDED:")
    
    if ca:
        print("\nAccounts gained compromised Access:")
        for count, account in enumerate(ca):
            print(f"{count}. {account}")

    else:
        print("\nAccounts gained compromised Access: None")
    
    print("\n" + "-"*80)
    
    # ========================== DISTRIBUTED CREDENTIAL ABUSE ======================
    print("\nDISTRIBUTED CREDENTIAL ABUSE RECORDED:")
    
    if dca:
        print("\nLocations Detected with Distributed Credential Abuse:")
        for count, location in enumerate(dca):
            print(f"{count}. {location}")
            
            # ======================= USERS UNDER LOCATION =========================
            if location in ipvs:
                users = ipvs[location].get("Total Users", set())
                for i, user in enumerate(users):
                    print(f"   {i}. {user}")
                print("\n")
    else:
        print("\nLocations Detected with Distributed Credential Abuse: None")
    
    print("\n" + "-"*80)
    
    # ========================== USER MOBILITY REPORTING ===========================
    print("\nUSER MOBILITY RECORDED:")
    
    if um:
        print("\nAccounts recorded with User Mobility:")
        for count, username in enumerate(um):
            print(f"\n{count}. {username}")
            
            # ========================= LOCATIONS UNDER USER =======================
            if username in accounts:
                locations = accounts[username].get("Total Locations", set())
                for i, location in enumerate(locations):
                    print(f"   {i}. {location}")
    else:
        print("\nAccounts recorded with User Mobility: None")
    
    # ============================== FINAL TERMINATION =============================
    print("\n" + "="*80)
    print("="*80)


# =============================== ANALYSIS FINAL PUBLISH ===============================
def publish_final_report(rep: tuple, bf: tuple, sa: set, ca: set, dca: set, umr: set, ipvs: dict, accounts: dict)->None:
    """
    Docstring for publish_final_report
    
    :param rep: THE PRELIMINARY REPORTS OF VALID, INVALID AND TOTAL LINES OF THE ORIGINAL LOG
    :type rep: tuple
    :param bf: BRUTE FORCE RECORDS [IP ADDRESSES, USERNAMES]
    :type bf: tuple
    :param sa: SUSTAINED ATTACKS LOCATION RECORDS
    :type sa: dict
    :param ca: COMPROMISED ACCESS ACCOUNTS RECORDS
    :type ca: dict
    :param dca: DISTRIBUTED CREDENTIAL ABUSE LOCATION RECORDS
    :type dca: set
    :param um: USER MOBILITY ACCOUNTS RECORDS
    :type um: set
    """

    width = 80
    final_report = f"FINAL_AUDIT_REPORT_FOR_[{sys.argv[1]}].txt"
    with open(final_report, "w") as f:
        f.write(f"-: FINAL AUDIT REPORT FOR {sys.argv[1]} :-".center(width) + "\n")
        f.write(("-" * 20).center(width) + "\n\n")
        f.write(
            f"Total Lines in {sys.argv[1]} file: {rep[0]}\n"
            f"Total Valid Lines in the file: {rep[1]}\n"
            f"Total Invalid Lines in the file: {rep[2]}\n\n"
        )
        f.write("======================================\n")

        f.write("\n")

        bf_user, bf_ip = bf
        f.write("BRUTE FORCE ACTIVITIES:\n")
        f.write("---\n")
        f.write("\n")
        if bf_user is None:
            f.write("No account with brute force activity detected\n")
        else:
            f.write("Accounts with Brute Force Activity:\n")
            for i, user in enumerate(bf_user, 1):
                f.write(f"{i}. {user}\n")
        f.write("\n")
        f.write("--------------------------------------\n")

        if bf_ip is None:
            f.write("No locations with brute force activity detected.\n")
        else:
            f.write("Locations with Brute Force Activity:\n")
            for i, ip in enumerate(bf_ip, 1):
                f.write(f"{i}. {ip}\n")
        f.write("\n")
        f.write("======================================\n")
        f.write("\n")
        f.write("SUSTAINED ACTIONS Locations:\n")
        if not sa:
            f.write("No Location profile detected.\n")
        else:
            i=0
            for i, location in enumerate(sa):
                f.write(f"{i}. {location}\n")

        f.write("\n")
        f.write("======================================\n")
        f.write("\n")
        f.write("COMPROMISED ACCESSES Accounts:\n")
        if not ca:
            f.write("No account profile detected.\n")
        else:
            for i, account in enumerate(ca):
                f.write(f"{i}. {account}\n")

        f.write("\n")
        f.write("======================================\n")
        f.write("\n")
        f.write("Locations with DISTRIBUTED CREDENTIAL ABUSE:")
        if not dca:
            f.write("No Location Recorded under Distributed Credential Abuse.\n")
        else:
            f.write("\n")
            i=0
            for i, ipv in enumerate(dca):
                f.write(f"{i}. {ipv}\n")

        f.write("\n")
        f.write("======================================\n")
        f.write("\n")
        f.write("Accounts with USER MOBILITY RISK:")
        if not umr:
            f.write("No Account Recorded under User Mobility Risk.\n")
        else:
            i=0
            f.write("\n")
            for ids in umr:
                i+=1
                f.write(f"{i}. {ids}\n")
        f.write("\n")
        f.write("======================================\n")
        f.write("\n")
        if not ipvs:
            f.write("No Location profile detected.\n")
        else:
            for location, dossier in ipvs.items():
                f.write(f"IP Address: {location}:\n")
                f.write("---\n")
                f.write("Users in the location:\n")
                for user in dossier["Total Users"]:
                    f.write(f"\t{user}\n")
                f.write("\n")
                f.write(
                    f"Whether Brute Force Detected: {dossier['Brute Force Detected']}\n"
                    f"Whether Sustained Activity Detected: {dossier['Sustained Action Detected']}\n"
                    f"Is suspicious for Distributed Credential Abuse: {dossier['Distributed Credential Abuse']}\n\n"
                    f"Total Attempts Recorded: {dossier['Total Attempts Recorded']}\n"
                    f"Attempts Failed: {dossier['Failed Attempts Recorded']}\n"
                    f"Attempts Successful: {dossier['Successful Attempts Recorded']}\n\n"
                )
                f.write("--------------------------------------\n")

        f.write("\n")
        f.write("======================================\n")
        f.write("\n")
        if not accounts:
            f.write("No account profile detected.\n")
        else:
            for account, dossier in accounts.items():
                f.write(f"Username: {account}:\n")
                f.write("---\n")
                f.write("Locations used by user:\n")
                for loc in dossier["Total Locations"]:
                    f.write(f"\t{loc}\n")
                f.write("\n")
                f.write(
                    f"Whether Brute Force Detected: {dossier['Brute Force Detected']}\n"
                    f"Whether the account gained Compromised Access: {dossier['Compromised Access Detected']}\n"
                    f"Is suspicious for User Mobility Risk: {dossier['User mobility']}\n\n"
                    f"Total Attempts Recorded: {dossier['Total Attempts Recorded']}\n"
                    f"Attempts Failed: {dossier['Failed Attempts Recorded']}\n"
                    f"Attempts Successful: {dossier['Successful Attempts Recorded']}\n\n"
                )
                f.write("--------------------------------------\n")
        
        f.write("\n\n\n")
        f.write("======================================\n".center(width))
        f.write("\n")
        f.write("-=| END OF REPORT |=-\n".center(width))
        f.write("\n")
        f.write("======================================\n".center(width))


# =========================== PARSING FOR VALID RECORDS ============================
def parsing(filename: str)->tuple[list, tuple, bool]:
    """
    Docstring for parsing
    
    :param l: For parsing the txt/csv file as csv.
              The required format for the log entries is:

    :type l: list
    :return: The valid entries in the login log entries.
    :rtype: list
    """
    validation=Validation()

    logs=[]

    valids=0; invalids=0; total_lines=0
    try:
        with open(filename, "r") as file:
            for line in file:
                if not line:
                    continue
                total_lines+=1
                line=line.strip()
                compiled, log=validation.validate(line)
                if compiled:
                    valids+=1
                    logs.append(log)
                    
                if not compiled:
                    invalids+=1
    except FileNotFoundError:
        sys.exit("[?] File not found")
    
    except (ValueError, TypeError, AttributeError):
        sys.exit("[!] Something went wrong")
    
    except EOFError:
        sys.exit("[!] Alert: Invalid input")
            
    print(f'''
        [+] total line(s) compiled = {valids}\n
        [-] total line(s) not compiled = {invalids}\n
        [+] total lines in original record = {total_lines}\n
        [!] lines/ record mis-matched = {total_lines - (valids + invalids)}
    ''')
    
    nums=(total_lines, valids, invalids)
    logs.sort(key=lambda x: dt.strptime(x[0], "%Y-%m-%d %H:%M:%S"))

    if len(logs)<=(total_lines//2):
        print("[-] The log data is manipulated.")
        return logs, nums, True
    
    if len(logs)==0:
        nums = 0,0,0
        print("[!] ALERT: Either not a valid file, or corrupted file.")
        return None, nums, True

    return logs, nums, False

# =============================== Log and threat analysis management ===============================
def analysis(file: str)->None:
    """
    Docstring for analysis
    
    :param file: The original log entries (in text, csv or log)
    :type file: str
    """
    if not file:
        sys.exit("[?] Enter a file name while calling the program.")

    records, reports, is_manipulated=parsing(file)

    valids,_,_ = reports

    if is_manipulated:
        if valids==0:
            sys.exit("""\n\n\n
                        =========================================
                        =========================================\n
                        [!] SYSTEM'S WARNING: NO VALID ENTRY RECORDED\n
                        =========================================
                        =========================================\n\n\n
                        """)
        else:
            print("\n\n\n")
            print("==========================================")
            print("[!] Alert: File is manipulated at most extent.")
            print("==========================================")
            print("\n\n\n")

    threats, data = threat_analysis(records)

    bf_users, bf_ipv4s, sa_ipv4s, dca_locations, ca_users, umr_accounts = threats
    location_records, id_records = data

    bruteforce=(bf_users, bf_ipv4s)

    display(bruteforce, sa_ipv4s, ca_users, dca_locations, umr_accounts, location_records, id_records)
    publish_final_report(reports, bruteforce, sa_ipv4s, ca_users, dca_locations, umr_accounts, location_records, id_records)


def main():
    """
    Docstring for main
    """

    if len(sys.argv)!=2:
        sys.exit("[-] Invalid Format of Entry.")
    
    if not (
        sys.argv[1].endswith(".txt") or
        sys.argv[1].endswith(".csv") or
        sys.argv[1].endswith(".log")
    ):
        sys.exit("[-] Not a valid file.")

    file=sys.argv[1]
    analysis(file)
    

if __name__=="__main__":
    main()