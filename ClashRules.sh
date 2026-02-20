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
      proxy_group_name = first_group['name']

      # =========================================================
      # PROXY GROUPS
      # =========================================================

      Value['proxy-groups'].push({
        'name'      => 'Azure_West_Europe',
        'type'      => 'url-test',
        'url'       => 'https://s3westeurope.blob.core.windows.net/public/latency-test.json',
        'interval'  => 300,
        'tolerance' => 50,
        'lazy'      => true,
        'proxies'   => proxies
      })

      Value['proxy-groups'].push({
        'name'      => 'Azure_US_East',
        'type'      => 'url-test',
        'url'       => 'https://s3eastus.blob.core.windows.net/public/latency-test.json',
        'interval'  => 300,
        'tolerance' => 50,
        'proxies'   => proxies
      })

      Value['proxy-groups'].push({
        'name'      => 'Azure_US_West',
        'type'      => 'url-test',
        'url'       => 'https://q9westus.blob.core.windows.net/public/latency-test.json',
        'interval'  => 300,
        'tolerance' => 50,
        'proxies'   => proxies
      })

      Value['proxy-groups'].push({'name' => 'South Africa 🇿🇦', 'type' => 'select', 'proxies' => proxies})
      Value['proxy-groups'].push({'name' => 'Brazil 🇧🇷',       'type' => 'select', 'proxies' => proxies})
      Value['proxy-groups'].push({'name' => 'CrunchyRoll',      'type' => 'select', 'proxies' => proxies})
      Value['proxy-groups'].push({'name' => 'Aus 🇦🇺',          'type' => 'select', 'proxies' => proxies})

      # =========================================================
      # RULE PROVIDERS
      # =========================================================

      Value['rule-providers'] ||= {}

      # Loyalsoldier
      {
        'reject'       => ['domain',    'reject.txt',        './ruleset/reject.yaml'],
        'private'      => ['domain',    'private.txt',       './ruleset/private.yaml'],
        'proxy'        => ['domain',    'proxy.txt',         './ruleset/proxy.yaml'],
        'direct'       => ['domain',    'direct.txt',        './ruleset/direct.yaml'],
        'gfw'          => ['domain',    'gfw.txt',           './ruleset/gfw.yaml'],
        'tld-not-cn'   => ['domain',    'tld-not-cn.txt',    './ruleset/tld-not-cn.yaml'],
        'telegramcidr' => ['ipcidr',    'telegramcidr.txt',  './ruleset/telegramcidr.yaml'],
        'cncidr'       => ['ipcidr',    'cncidr.txt',        './ruleset/cncidr.yaml'],
        'lancidr'      => ['ipcidr',    'lancidr.txt',       './ruleset/lancidr.yaml'],
        'applications' => ['classical', 'applications.txt',  './ruleset/applications.yaml']
      }.each do |name, (behavior, file, path)|
        Value['rule-providers'][name] = {
          'type'     => 'http',
          'behavior' => behavior,
          'url'      => \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/#{file}\",
          'path'     => path,
          'interval' => 86400
        }
      end

      # Azure - ipcidr behavior (raw CIDRs, no prefix)
      Value['rule-providers']['Azure_West_Europe'] = {
        'type'     => 'http',
        'behavior' => 'ipcidr',
        'url'      => 'https://raw.githubusercontent.com/gorillapower/azure-ips-westeurope-clash/refs/heads/main/azure_west_europe.yaml',
        'path'     => './rule_provider/azure_west_europe.yaml',
        'interval' => 86400
      }

      Value['rule-providers']['Azure_US_East'] = {
        'type'     => 'http',
        'behavior' => 'ipcidr',
        'url'      => 'https://raw.githubusercontent.com/gorillapower/azure-ips-westeurope-clash/refs/heads/main/azure_us_east.yaml',
        'path'     => './rule_provider/azure_us_east.yaml',
        'interval' => 86400
      }

      Value['rule-providers']['Azure_US_West'] = {
        'type'     => 'http',
        'behavior' => 'ipcidr',
        'url'      => 'https://raw.githubusercontent.com/gorillapower/azure-ips-westeurope-clash/refs/heads/main/azure_us_west.yaml',
        'path'     => './rule_provider/azure_us_west.yaml',
        'interval' => 86400
      }

      # =========================================================
      # RULES
      #
      # Nuke original rules and build from scratch.
      # Unshift in reverse priority (lowest first).
      #
      # Order in config (top = highest priority):
      #   1. Azure
      #   3. Australia
      #   2. South Africa
      #   4. CrunchyRoll
      #   5. Loyalsoldier
      #   6. MATCH (catch-all)
      # =========================================================

      Value['rules'] = []

      # Catch-all (bottom of the list)
      Value['rules'].push('MATCH,' + proxy_group_name)

      # 5. Loyalsoldier
      [
        'RULE-SET,applications,DIRECT',
        'RULE-SET,private,DIRECT',
        'RULE-SET,reject,REJECT',
        'RULE-SET,tld-not-cn,' + proxy_group_name,
        'RULE-SET,gfw,'        + proxy_group_name,
        'RULE-SET,proxy,'      + proxy_group_name,
        'RULE-SET,direct,DIRECT',
        'RULE-SET,lancidr,DIRECT',
        'RULE-SET,cncidr,DIRECT',
        'RULE-SET,telegramcidr,' + proxy_group_name,
        'GEOIP,LAN,DIRECT',
        'GEOIP,CN,DIRECT'
      ].reverse.each { |r| Value['rules'].unshift(r) }

    
      # 3. CrunchyRoll
      [
        'DOMAIN-SUFFIX,crunchyroll.com,CrunchyRoll',
        'AND,((SRC-IP-CIDR,10.0.0.235/32),(DOMAIN,firebaseremoteconfigrealtime.googleapis.com)),CrunchyRoll'
      ].reverse.each { |r| Value['rules'].unshift(r) }


      # South Africa
      [
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
      ].reverse.each { |r| Value['rules'].unshift(r) }


      #  Australia
      [
        'DOMAIN-SUFFIX,stan.com.au,Aus 🇦🇺',
        'DOMAIN-SUFFIX,stan.video,Aus 🇦🇺',
        'DOMAIN-SUFFIX,stan.akamaized.net,Aus 🇦🇺',
        'DOMAIN-SUFFIX,stan.sakamai.net,Aus 🇦🇺',
        'DOMAIN-SUFFIX,youboranqs01.com,Aus 🇦🇺',
        'DOMAIN-SUFFIX,nice264.com,Aus 🇦🇺',
        'DOMAIN-SUFFIX,akamaihd.net,Aus 🇦🇺',
        'GEOIP,AU,Aus 🇦🇺'
      ].reverse.each { |r| Value['rules'].unshift(r) }



      # 1. Azure (highest priority)
      Value['rules'].unshift('RULE-SET,Azure_US_West,Azure_US_West')
      Value['rules'].unshift('RULE-SET,Azure_US_East,Azure_US_East')
      Value['rules'].unshift('RULE-SET,Azure_West_Europe,Azure_West_Europe')

    end

    File.open('$CONFIG_FILE','w') {|f| YAML.dump(Value, f)}
    puts '${LOGTIME} Clash rules configured successfully'
  rescue Exception => e
    puts '${LOGTIME} Error: ' + e.message
  end
" 2>/dev/null >> $LOG_FILE

exit 0