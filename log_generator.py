import random
from pytz import timezone as tz
from datetime import datetime as dt, timedelta as td

def location()->list:
    total_ips=25500

    locations=[]
    repeats=[]
    for i in range(total_ips):
        loc=""
        for i in range(4):
            loc+=str(random.randint(0,255))
            if i!=3:
                loc+="."
        if loc in locations:
            repeats.append(loc)
        locations.append(loc)
        
    return locations, repeats

def usernames():
    total_ids=25000

    users=[]
    repeats=[]
    for i in range(total_ids):
        user="user_"
        for j in range(random.choice(range(4,12))):
            user+=random.choice("abcdefghijklmnopqrstuvwxyz_0123456789_")
        if user in users:
            repeats.append(user)
        users.append(user)
    
    return users, repeats

def store():
    results=[]
    users, repeated_users=usernames()
    ips, repeated_ips=location()

    combinations=25600
    for i in range(combinations):
        user=random.choice(users)
        ip=random.choice(ips)
        results.append([user, ip])
    
    return results, repeated_users, repeated_ips

fakes=[
    ["fake", "0.0.0.0"],
    ["unknown", 5.0],
    ["irrelevant", "123.456.789.000"],
    ["neglect", "fake_location"]
    ]

def random_missed(n):
    missed=[]
    for i in range(n//25):
        missed.append(random.randint(0, n-1))

    return missed

def main():
    current=dt.now(tz("Asia/Kolkata"))
    records, repeated_users, repeated_ips=store()

    if not repeated_users:
        print("No repeated users")
    else:
        for user in repeated_users:
            print(user)

    if not repeated_ips:
        print("No repeated IPs")
    else:
        for ip in repeated_ips:
            print(ip)

    with open("evidences.log", "w") as f:
        total_records=110000
        for i in range(total_records):
            if i+1 in random_missed(total_records):
                num=random.choice(range(100))/10
                record=random.choice(fakes)
                status=random.choice(['error', 'warning', 'None', ''])
                current+=td(seconds=num)
            
            else:
                num=random.choice(range(100))/10
                record=random.choice(records)
                status=random.choice(['fail', 'fail', 'fail', 'fail', 'success', 'fail', 'fail', 'fail', 'fail'])
                current+=td(seconds=num)

            f.write(f"{current.strftime('%Y-%m-%d %H:%M:%S')},{record[0]},{record[1]},{status}\n")

if __name__=="__main__":
    main()