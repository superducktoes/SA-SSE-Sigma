import sys
import subprocess
import yaml
import json
import re

path_to_tools = "/root/sigma/tools"

def generate_output(data, search_output, rule_path):

    # use this to get the link to the github page
    page_link = "https://github.com/Neo23x0/sigma/blob/master/{}".format(rule_path[12:])

    # get the rule name from the path and remove extension
    rule_name = (rule_path.split("/")[-1]).split(".")[0]

    # get the first reference. if there isn't one generate a link to the github page
    if "references" in data:
        reference = data['references'][0]
    elif "reference" in data:
        reference = data['reference'][0]
    else:
        m = re.search("(rules.*)", rule_path)
        if m:
            reference = "https://github.com/Neo23x0/sigma/blob/master/{}".format(m.group(1))
        

    # get the mitre attack references and build our string
    attack_reference_string = ""
    if "tags" in data:
        for i in data['tags']:
            if ".t" in i:
                i = "|" + i.upper().split(".")[1]
                attack_reference_string += i

    # try to figure out a category
    if ("exploit" or "apt") in rule_name.lower():
        category = "Adversary Tactics"
    elif "cloud" in rule_path:
        category = "SaaS"
    elif "compliance" in rule_path:
        category = "Compliance"
    elif "network" in rule_path:
        category = "Network Attack"
    elif "web" in rule_path:
        category = "Web Attack"
    else:
        category = "Adversary Tactics"

    # get false positives data
    if "falsepositives" in data:
        false_positives = data['falsepositives'][0]
    else:
        false_positives = "None"

    # make a guess as to what the data source is. If nothing fall back to all logs
    stage = "Stage_1"
    if "windows" in rule_path:
        data_source_category = "VendorSpecific-winsec"
    elif "aws" in rule_path:
        data_source_category = "VendorSpecific-aws-cloudtrail"
        stage = "Stage_3"
    elif "proxy" in rule_path:
        data_source_category = "DS005WebProxyRequest-ET01Requested"
    elif "linux" in rule_path:
        data_source_category = "DS009EndPointIntel"


    # make a guess about the domain
    if ("linux" or "windows") in rule_path:
        domain = "Endpoint"
    elif "network" in rule_path:
        domain = "Network"
    else:
        domain = "Access"
    parsed_data = {
        rule_name:
        {
            "name": data['title'],
            "alertVolume": "Low",
            "inSplunk": "yes",
            "journey": stage,
            "usecase": "Security Monitoring",
            "highlight": "No",
            "id": rule_name,
            "channel": "Sigma",
            "alertvolume": "Other",
            "category": category,
            "domain": domain,
            "killchain": "",
            "SPLEase": "None",
            "searchKeywords": "",
            "icon": "Core_Use_Case.png",
            "company_logo": "https://raw.githubusercontent.com/Neo23x0/sigma/master/images/Sigma_0.3.png",
            "company_name": "Sigma",
            "company_description": "Sigma is a generic and open signature format that allows you to describe relevant log events in a straight forward manner. The rule format is very flexible, easy to write and applicable to any type of log file. The main purpose of this project is to provide a structured form in which researchers or analysts can describe their once developed detection methods and make them shareable with others.\n Author: {}".format(data['author']),
            "company_link": page_link,
            "dashboard": "showcase_custom?showcaseId={}".format(rule_name),
            "help": "Help not needed",
            "knownFP": false_positives,
            "data_source_categories": data_source_category,
            "mitre_technique": attack_reference_string,
            "mitre_tactic":"",
            "app": "Sigma",
            "displayapp": "Sigma",
            "hasSearch": "Yes",
            "featured": "No",
            "additional_context": [{
                "search": search_output,
                "open_panel": True,
                "title": data['title'],
                "detail": data['description'],
                "link": reference
                }
            ]
        }
    }
    
    return json.dumps(parsed_data)

if __name__ == "__main__":

    if len(sys.argv) == 2:
        #  ~/sigma/tools/sigmac -t splunk -c ~/sigma/tools/config/splunk-windows.yml ~/sigma/rules/windows/process_creation/win_susp_whoami.yml
        
        # get the name of the rule
        rule_path = sys.argv[1]
            
        command = "{}/sigmac -t splunk -c {}/config/splunk-windows.yml {}".format(path_to_tools, path_to_tools, rule_path)

        # use sigmac to get the output of what the search command will look like
        search_output = subprocess.run([command], shell=True, stdout=subprocess.PIPE).stdout.decode('utf-8')
        
        # parse the rest of the rule file to get additional information
        with open(rule_path) as f:
            data = yaml.load(f, Loader=yaml.FullLoader)
            parsed_data = generate_output(data, search_output, rule_path)
            print(parsed_data)
    else:
        print("Please enter the path to the rule")
        print("e.x. python3 generate_content.py ~/sigma/rules/windows/process_creation/win_susp_whoami.yml")
