#!/bin/sh
. /usr/share/openclash/ruby.sh
. /usr/share/openclash/log.sh
. /lib/functions.sh

LOG_OUT "Configuring custom Clash rules..."
LOGTIME=$(date "+%Y-%m-%d %H:%M:%S")
LOG_FILE="/tmp/openclash.log"
CONFIG_FILE="$1"

ruby -ryaml -rYAML -I "/usr/share/openclash" -E UTF-8 -e "
  begin
    Value = YAML.load_file('$CONFIG_FILE')
    first_group = Value['proxy-groups'][0]
    
    if first_group && first_group['proxies']
      proxies = first_group['proxies']

      Value['proxy-groups'].push({
        'name' => 'Azure_West_Europe',
        'type' => 'url-test',
        'url' => 'https://s3westeurope.blob.core.windows.net/public/latency-test.json',
        'interval' => 300,
        'tolerance' => 50,
        'lazy' => true,
        'proxies' => proxies
      })
      
      # --- 1. AZURE US GROUPS ---
      # US East (covers East US, East US 2)
      Value['proxy-groups'].push({
        'name' => 'Azure_US_East',
        'type' => 'url-test',
        'url' => 'http://s3eastus.blob.core.windows.net/public/latency-test.json', 
        'interval' => 300,
        'tolerance' => 50,
        'proxies' => proxies
      })

      # US West (covers West US, West US 2, West US 3)
      Value['proxy-groups'].push({
        'name' => 'Azure_US_West',
        'type' => 'url-test',
        'url' => 'http://s3westus.blob.core.windows.net/public/latency-test.json', 
        'interval' => 300,
        'tolerance' => 50,
        'proxies' => proxies
      })

      Value['proxy-groups'].push({'name' => 'South Africa 🇿🇦', 'type' => 'select', 'proxies' => proxies})
      Value['proxy-groups'].push({'name' => 'Brazil 🇧🇷', 'type' => 'select', 'proxies' => proxies})
      Value['proxy-groups'].push({'name' => 'CrunchyRoll', 'type' => 'select', 'proxies' => proxies})
      Value['proxy-groups'].push({'name' => 'Aus 🇦🇺', 'type' => 'select', 'proxies' => proxies})

      Value['rule-providers'] ||= {}
      Value['rule-providers']['Azure_West_Europe'] = {
        'type' => 'http',
        'behavior' => 'classical',
        'url' => 'https://raw.githubusercontent.com/gorillapower/azure-ips-westeurope-clash/refs/heads/main/azure_west_europe.yaml',
        'path' => './rule_provider/azure_west_europe.yaml',
        'interval' => 86400
      }

      Value['rule-providers']['Azure_US_East'] = {
        'type' => 'http',
        'behavior' => 'classical',
        'url' => 'https://raw.githubusercontent.com/gorillapower/azure-ips-westeurope-clash/refs/heads/main/azure_us_east.yaml',
        'path' => './rule_provider/azure_us_east.yaml',
        'interval' => 86400
      }

      Value['rule-providers']['Azure_US_West'] = {
        'type' => 'http',
        'behavior' => 'classical',
        'url' => 'https://raw.githubusercontent.com/gorillapower/azure-ips-westeurope-clash/refs/heads/main/azure_west_east.yaml',
        'path' => './rule_provider/azure_us_west.yaml',
        'interval' => 86400
      }
      Value['rules'].unshift('RULE-SET,Azure_West_Europe,Azure_West_Europe')
      Value['rules'].unshift('RULE-SET,Azure_US_East,Azure_US_East')
      Value['rules'].unshift('RULE-SET,Azure_US_West,Azure_US_West')
      
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

      cr_rules = [
        'DOMAIN-SUFFIX,crunchyroll.com,CrunchyRoll',
        'AND,((SRC-IP-CIDR,10.0.0.232/32),(DOMAIN,firebaseremoteconfigrealtime.googleapis.com)),CrunchyRoll'
      ]
      cr_rules.reverse.each { |r| Value['rules'].unshift(r) }

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
    
    File.open('$CONFIG_FILE','w') {|f| YAML.dump(Value, f)}
    puts '${LOGTIME} Clash rules configured successfully'
  rescue Exception => e
    puts '${LOGTIME} Error: ' + e.message
  end
" 2>/dev/null >> $LOG_FILE

exit 0