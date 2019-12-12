#!/bin/bash
#Author: Di0nj@ck - 12/05/19
#Version: 1.0

# WHOIS Extractor is a tool for automatic extraction of interesting data/fields from WHOIS server responses on a bunch of domains or IPs
#*******************************************************************************************************************

#CONFIG VARIABLES
APP_VERSION=1.0
APP_DIR=$(pwd)
SCRIPT_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S")

#GLOBAL VARIABLES
input_file="$1"
report_file="whois_data.txt"
targets_list=()
resolve_domains=0 #Resolve Domains into IPs

whois_results_list=()
whois_domain_items_list=( #CUSTOMIZABLE LIST OF WHOIS ITEMS TO RETRIEVE ON WHOIS DOMAIN QUERY
    'Domain Name:'
    'Registrar:'
    'Creation Date:'
    'Updated Date:'
    'Name Server:'
    'Registrant Name:'
    'Registrant Organization:'
    'Registrant City:'
    'Registrant Country:'
    'Registrant Email:'
    'Admin Name:'
    'Admin Organization:'
    'Admin City:'
    'Admin Country:'
    'Admin Email:'
    'Tech Name:'
    'Tech Organization:'
    'Tech City:'
    'Tech Country:'
    'Tech Email:'
)

whois_ip_items_list=( #CUSTOMIZABLE LIST OF WHOIS ITEMS TO RETRIEVE ON WHOIS DOMAIN QUERY
    'NetRange:'
    'CIDR:'
    'NetName:'
    'OriginAS:'
    'RegDate:'
    'Updated:'
    'City:'
    'Country:'
    'Organization:'
    'CustName:'
)

whois_key_findings=( #KEY ELEMENTS TO FIND FOR AND PARSE INTO OUR WHOIS RESULTS (BOTH DOMAIN AN IP)
    'Registrar:'
    'Name Server:'
    'NetName:'
    'OriginAS:'
    'Organization:'
)

#************************************************************************************

#LOAD FILE INTO ARRAY
function load_file_into_array {
    
    readarray -t targets_list < "$1"
}


#LOAD TARGETS TO ANALYZE
function run_whois {

    cnt=${#targets_list[@]}
    i=0
    
    for a_target in "${targets_list[@]}";do     
        output=$(whois -I $a_target)
        ip=$(getent hosts $a_target | head -n 1 | cut -d ' ' -f 1)

        printf '    [%d/%d] Querying: %s (IP: %s)\n' "$((i + 1))" "$cnt" "$a_target" "$ip"

        #IS A DOMAIN, CHECK IF WE WANT TO RESOLVE IT AND WHOIS THE IP ALSO
        if [[ "$output" == *"Domain Name:"* ]];then
            if [[ $resolve_domains -eq 1 ]];then
                output_ip=$(whois -I $ip)
                results=$(printf '[*] %s (IP: %s):\n%s\n%s\n' "$a_target" "$ip" "$output" "$output_ip")
            fi
        else
            results=$(printf '[*] %s (IP: %s):\n%s\n' "$a_target" "$ip" "$output")
        fi
        whois_results_list+=( "$results" ) 
        i=$i+1
    done
    
}

#PARSE WHOIS RESULTS AND SAVE ON FILE
function output_results {
    exec 3<> "$report_file"
    SAVEIFS=$IFS   # Save current IFS
    
    for whois_response in "${whois_results_list[@]}";do

        target=$(echo "$whois_response" | sed -n 1p)

        merged_grep_lists=( "${whois_domain_items_list[@]}" "${whois_ip_items_list[@]}" )
        grep_targets=$(IFS='|';echo "${merged_grep_lists[*]}";IFS=$' \t\n')

        #if [[ "$whois_response" == *"Domain Name:"* ]];then #WHOIS RESULT OF A DOMAIN NAME
        #    grep_targets=$(IFS='|';echo "${whois_domain_items_list[*]}";IFS=$' \t\n')
        #elif [[ "$whois_response" == *"NetName:"* ]];then #WHOIS RESULT OF AN IP
        #    grep_targets=$(IFS='|';echo "${whois_ip_items_list[*]}";IFS=$' \t\n')
        #elif [[ "$whois_response" == *"Domain Name:"* && "$whois_response" == *"NetName:"*]];then #DOMAIN NAME WHOIS INCLUDING RESOLVED IP WHOIS DATA
            
        #fi
        results=$(echo "$whois_response" | grep -i -E "$grep_targets")
        registered_or_not=$(echo "$whois_response" | grep -i -E "^No match|^NOT FOUND|^Not fo|AVAILABLE|^No Data Fou|has not been regi|No entri")
        IFS=$'\n'

        #SAVE RESULTS ON FILE
        if ! [ -z "$results" ];then #IF NOT EMPTY RESULTS, SAVE OUTPUT TO FILE
            printf '%s\n%s\n' "$target" "$results" >&3
        elif ! [ -z "$registered_or_not" ];then #IF DOMAIN OR IP ARE NOT REGISTERED ON WHOIS DATABASE
            printf '%s\n%s\n' "$target" "WARNING. Not registered Domain/IP " >&3
        else
            printf '%s\n%s\n' "$target" "ERROR. Whois query has failed!" >&3
            continue
        fi
    done

    #SUMMARY OF KEY FINDINGS
    printf '[*] Extracting a summary of key findings...\n'
    IFS=$'\n'
    printf '\n%s\n\n' "*** SUMMARY OF KEY FINDINGS *** (sorted)" >&3

    for key_item in "${whois_key_findings[@]}";do
        results=$(cat $report_file | grep -i "$key_item" | sort | uniq -c | sort -n)
        printf '%s\n\n' "$results" >&3
    done
    IFS=$SAVEIFS
}

#************************************************************************************
#**** MAIN CODE ****

if [[ "$2" == "resolve" ]];then #READ INPUT ARGUMENT FOR OPTIONALLY 'RESOLVE' DOMAINS INTO IPs
    printf '\n[INFO] Resolve Domains enabled\n\n'
    resolve_domains=1
fi

#READ INPUT FILE WITH TARGETS INTO AN ARRAY
printf '[*] Loading input file of IPs-Domains...\n'
load_file_into_array "$input_file"

#LAUNCH WHOIS CLIENT
printf '[*] Performing WHOIS calls...\n'
run_whois

#SAVE RESULTS
printf '[*] Grepping and saving results to a file...\n'
output_results

printf '[*] FINISHED. ALL DONE!\n'