#!/bin/sh
. /usr/share/openclash/ruby.sh
. /usr/share/openclash/log.sh
. /lib/functions.sh

LOG_OUT "Tip: Start Running Custom Overwrite Scripts..."
LOGTIME=$(echo $(date "+%Y-%m-%d %H:%M:%S"))
LOG_FILE="/tmp/openclash.log"
CONFIG_FILE="$1"

ruby -ryaml -rYAML -I "/usr/share/openclash" -E UTF-8 -e "
  begin
    Value = YAML.load_file('$CONFIG_FILE');
    first_group = Value['proxy-groups'][0]
    
    if first_group && first_group['proxies']
      proxies = first_group['proxies']

      # --- 1. PROXY GROUPS ---
      
      # Azure West Europe
      Value['proxy-groups'].push({'name' => 'Azure_West_Europe', 'type' => 'select', 'proxies' => proxies})
      
      # South Africa
      Value['proxy-groups'].push({'name' => 'South Africa 🇿🇦', 'type' => 'select', 'proxies' => proxies})
      
      # Brazil
      Value['proxy-groups'].push({'name' => 'Brazil 🇧🇷', 'type' => 'select', 'proxies' => proxies})
      
      # CrunchyRoll
      Value['proxy-groups'].push({'name' => 'CrunchyRoll', 'type' => 'select', 'proxies' => proxies})
      
      # Australia
      Value['proxy-groups'].push({'name' => 'Aus 🇦🇺', 'type' => 'select', 'proxies' => proxies})

      # --- 2. RULE PROVIDER (Azure) ---
      Value['rule-providers'] ||= {}
      Value['rule-providers']['Azure_West_Europe'] = {
        'type' => 'http',
        'behavior' => 'classical',
        'url' => 'https://raw.githubusercontent.com/gorillapower/azure-ips-westeurope-clash/refs/heads/main/azure_west_europe.yaml',
        'path' => './rule_provider/azure_west_europe.yaml',
        'interval' => 86400
      }

      # --- 3. RULES (PRESERVED & NEW) ---
      
      # Azure Rule (Top Priority)
      Value['rules'].unshift('RULE-SET,Azure_West_Europe,Azure_West_Europe')

      # South Africa Rules (Preserved)
      sa_rules = [
        'IP-CIDR,66.22.96.0/24,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,akamaized.net,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,akamai.net,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,amazontrust.com,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,akamaietp.net,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,akamai-access.com,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,akaetp.net,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,akadns.net,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,segment.io,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,videoplaza.tv,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,bitmovin.com,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,dstv.com,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,dstv.stream,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,sdk.awswaf.com,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,permutive.com,South Africa 🇿🇦',
        'DOMAIN-SUFFIX,hotjar.com,South Africa 🇿🇦',
        'GEOIP,ZA,South Africa 🇿🇦'
      ]
      sa_rules.reverse.each { |r| Value['rules'].unshift(r) }

      # CrunchyRoll Rules (Preserved)
      cr_rules = [
        'DOMAIN-SUFFIX,crunchyroll.com,CrunchyRoll',
        'AND,((SRC-IP-CIDR,10.0.0.232/32),(DOMAIN,firebaseremoteconfigrealtime.googleapis.com)),CrunchyRoll'
      ]
      cr_rules.reverse.each { |r| Value['rules'].unshift(r) }

      # Australia Rules (Preserved)
      au_rules = [
        'DOMAIN-SUFFIX,stan.com.au,Aus 🇦🇺',
        'DOMAIN-SUFFIX,stan.video,Aus 🇦🇺',
        'DOMAIN-SUFFIX,youboranqs01.com,Aus 🇦🇺',
        'DOMAIN-SUFFIX,nice264.com,Aus 🇦🇺',
        'DOMAIN-SUFFIX,akamaihd.net,Aus 🇦🇺',
        'GEOIP,AU,Aus 🇦🇺'
      ]
      au_rules.reverse.each { |r| Value['rules'].unshift(r) }
      
    end
    
    File.open('$CONFIG_FILE','w') {|f| YAML.dump(Value, f)};
  rescue Exception => e
    puts '${LOGTIME} Error: Custom Overwrite failed - ' + e.message;
  end
" 2>/dev/null >> $LOG_FILE

exit 0