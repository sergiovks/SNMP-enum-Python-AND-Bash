#!/bin/bash

while getopts ":t:w:" opt; do
  case ${opt} in
    t )
      target_ip=$OPTARG
      ;;
    w )
      wordlist=$OPTARG
      ;;
    \? )
      echo "Invalid option: -$OPTARG" 1>&2
      exit 1
      ;;
    : )
      echo "Invalid option: -$OPTARG requires an argument" 1>&2
      exit 1
      ;;
  esac
done
shift $((OPTIND -1))

if [[ -z "${target_ip}" ]]; then
  echo "Target IP is required. Use -t option to specify the target IP." 1>&2
  exit 1
fi

if [[ -n "${wordlist}" ]]; then
  while read -r community_string; do
    #Enum Windows Users
    snmpwalk -c "${community_string}" -v1 "${target_ip}" 1.3.6.1.4.1.77.1.2.25

    #Enum running windows processes
    snmpwalk -c "${community_string}" -v1 "${target_ip}" 1.3.6.1.2.1.25.4.2.1.2

    #Enum open TCP ports
    snmpwalk -c "${community_string}" -v1 "${target_ip}" 1.3.6.1.2.1.6.13.1.3

    #Enum installed software
    snmpwalk -c "${community_string}" -v1 "${target_ip}" 1.3.6.1.2.1.25.6.3.1.2
  done < "${wordlist}"
else
  # Use default 'public' community string
  #Enum Windows Users
  snmpwalk -c public -v1 "${target_ip}" 1.3.6.1.4.1.77.1.2.25

  #Enum running windows processes
  snmpwalk -c public -v1 "${target_ip}" 1.3.6.1.2.1.25.4.2.1.2

  #Enum open TCP ports
  snmpwalk -c public -v1 "${target_ip}" 1.3.6.1.2.1.6.13.1.3

  #Enum installed software
  snmpwalk -c public -v1 "${target_ip}" 1.3.6.1.2.1.25.6.3.1.2
fi
