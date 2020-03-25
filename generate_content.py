import sys
import subprocess
import yaml
import json
import re

path_to_tools = "/root/sigma/tools"

def generate_output(data, search_output, rule_path):

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
    if "windows" in rule_path:
        data_source_category = "VendorSpecific-winsec"
    elif "aws" in rule_path:
        data_source_category = "VendorSpecific-aws-cloudtrail"
    elif "proxy" in rule_path:
        data_source_category = "DS005WebProxyRequest-ET01Requested"
    else:
        data_source_category = "VendorSpecific-AnySplunk"


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
            "SPLEase": "None",
            "alertvolume": "Low",
            "app": "Sigma",
            "category": category,
            "dashboard": "showcase_custom?showcaseId={}".format(rule_name),
            "data_source_categories": data_source_category,
            "description": data['description'],
            "displayapp": "Sigma",
            "additional_context": [{
                "search": search_output,
                "open_panel": True,
                "title": data['title'],
                "link": reference
                }],
            "domain": domain,
            "hasSearch": "Yes",
            "help": "Help not needed",
            "highlight": "No",
            "icon": "Core_Use_Case.png",
            "includeSSE": "Yes",
            "journey": "Stage_1",
            "knownFP": false_positives,
            "mitre": "",
            "mitre_tactic":"",
            "mitre_technique": attack_reference_string,
            "name": data['title'],
            "released": "3.0.0",
            "searchKeywords": "",
            "search_name": "",
            "usecase": "Security Monitoring"
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