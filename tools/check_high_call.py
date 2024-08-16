

def check_call():
    with open('/home/ops/hids/hids-go.log') as file:
        content=file.readlines()

    result={}
    for line in content:
        line=line.strip()
        if "Entry ->" in line:
            line=line.split(" CST ")[1]
            line=line.split("|||")[0]
            line=line.replace("  "," ")
            items=line.split(" ")
            if not result.has_key(items[4]):
                result.update({items[4]:0})
            else:
                count=result[items[4]]+1
                result.update({items[4]:count})

    for key in result.keys():
        if result[key]>1000:
            print(key,result[key])

def check_ss():
    with open('/home/ops/hids/hids-go.log') as file:
        content=file.readlines()

    result={}
    for line in content:
        line=line.strip()
        if "socket info" in line:
            line=line.split(" CST ")[1]
            line=line.replace("  "," ")
            items=line.split(" ")
            target=items[0].replace("[","")
            if not result.has_key(target):
                result.update({target:0})
            else:
                count=result[target]+1
                result.update({target:count})

    for key in result.keys():
        if result[key]>10:
            print(key,result[key])

check_call()
print("---------------------------------------")
check_ss()