#!/bin/sh
. /usr/share/openclash/ruby.sh
. /usr/share/openclash/log.sh
. /lib/functions.sh

LOG_OUT "Configuring custom Clash rules..."
LOGTIME=$(date "+%Y-%m-%d %H:%M:%S")
LOG_FILE="/tmp/openclash.log"
CONFIG_FILE="$1"

echo "${LOGTIME} [ClashRules] Script started. CONFIG_FILE='${CONFIG_FILE}'" >> $LOG_FILE

if [ -z "$CONFIG_FILE" ]; then
  echo "${LOGTIME} [ClashRules] ERROR: CONFIG_FILE is empty — script is running from the WRONG HOOK." >> $LOG_FILE
  echo "${LOGTIME} [ClashRules] This script must be placed in 'Overwrite Settings', not 'Developer Settings / Firewall Rules'." >> $LOG_FILE
  exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
  echo "${LOGTIME} [ClashRules] ERROR: CONFIG_FILE path '${CONFIG_FILE}' does not exist on disk." >> $LOG_FILE
  exit 1
fi

echo "${LOGTIME} [ClashRules] CONFIG_FILE exists, proceeding with YAML modification." >> $LOG_FILE

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

      ms_index = Value['proxy-groups'].index { |g| g['name'] == 'Microsoft' }
      tiva_group = {'name' => 'MicrosoftTiva', 'type' => 'select', 'proxies' => ['DIRECT'] + proxies}
      if ms_index
        Value['proxy-groups'].insert(ms_index + 1, tiva_group)
      else
        Value['proxy-groups'].push(tiva_group)
      end
      Value['proxy-groups'].push({'name' => 'South Africa 🇿🇦', 'type' => 'select', 'proxies' => proxies})
      Value['proxy-groups'].push({'name' => 'Brazil 🇧🇷',       'type' => 'select', 'proxies' => proxies})
      Value['proxy-groups'].push({'name' => 'CrunchyRoll',      'type' => 'select', 'proxies' => proxies})
      Value['proxy-groups'].push({'name' => 'Aus 🇦🇺',          'type' => 'select', 'proxies' => proxies})

      # =========================================================
      # RULE PROVIDERS
      # =========================================================

      Value['rule-providers'] ||= {}

      # Loyalsoldier (disabled - using subscription rules instead)
      # {
      #   'reject'       => ['domain',    'reject.txt',        './ruleset/reject.yaml'],
      #   'icloud'       => ['domain',    'icloud.txt',        './ruleset/icloud.yaml'],
      #   'apple'        => ['domain',    'apple.txt',         './ruleset/apple.yaml'],
      #   'google'       => ['domain',    'google.txt',        './ruleset/google.yaml'],
      #   'proxy'        => ['domain',    'proxy.txt',         './ruleset/proxy.yaml'],
      #   'direct'       => ['domain',    'direct.txt',        './ruleset/direct.yaml'],
      #   'private'      => ['domain',    'private.txt',       './ruleset/private.yaml'],
      #   'gfw'          => ['domain',    'gfw.txt',           './ruleset/gfw.yaml'],
      #   'greatfire'    => ['domain',    'greatfire.txt',     './ruleset/greatfire.yaml'],
      #   'tld-not-cn'   => ['domain',    'tld-not-cn.txt',    './ruleset/tld-not-cn.yaml'],
      #   'telegramcidr' => ['ipcidr',    'telegramcidr.txt',  './ruleset/telegramcidr.yaml'],
      #   'cncidr'       => ['ipcidr',    'cncidr.txt',        './ruleset/cncidr.yaml'],
      #   'lancidr'      => ['ipcidr',    'lancidr.txt',       './ruleset/lancidr.yaml'],
      #   'applications' => ['classical', 'applications.txt',  './ruleset/applications.yaml']
      # }.each do |name, (behavior, file, path)|
      #   Value['rule-providers'][name] = {
      #     'type'     => 'http',
      #     'behavior' => behavior,
      #     'url'      => "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/#{file}",
      #     'path'     => path,
      #     'interval' => 86400
      #   }
      # end

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

      Value['rule-providers']['Microsoft_Teams'] = {
        'type'     => 'http',
        'behavior' => 'ipcidr',
        'url'      => 'https://raw.githubusercontent.com/gorillapower/azure-ips-westeurope-clash/refs/heads/main/microsoft_teams.yaml',
        'path'     => './rule_provider/microsoft_teams.yaml',
        'interval' => 86400
      }

      # =========================================================
      # RULES
      #
      # Prepend custom rules on top of subscription rules.
      # Unshift in reverse priority (lowest first).
      #
      # Order in config (top = highest priority):
      #   1. MicrosoftTiva AND rules (tiva 10.0.0.188, mirrors Microsoft group)
      #   2. Azure CIDR (West Europe, US East, US West)
      #   3. Australia
      #   4. South Africa
      #   5. CrunchyRoll
      #   6. [subscription rules + catch-all]
      # =========================================================

      # Loyalsoldier (disabled - using subscription rules instead)
      # Value['rules'] = []
      # Value['rules'].push('MATCH,' + proxy_group_name)
      # [
      #   'RULE-SET,applications,DIRECT',
      #   'RULE-SET,private,DIRECT,no-resolve',
      #   'RULE-SET,reject,REJECT',
      #   'RULE-SET,icloud,DIRECT',
      #   'RULE-SET,apple,DIRECT',
      #   'RULE-SET,google,'     + proxy_group_name,
      #   'RULE-SET,proxy,'      + proxy_group_name,
      #   'RULE-SET,direct,DIRECT',
      #   'RULE-SET,tld-not-cn,' + proxy_group_name,
      #   'RULE-SET,telegramcidr,' + proxy_group_name + ',no-resolve',
      #   'RULE-SET,cncidr,DIRECT,no-resolve',
      #   'RULE-SET,lancidr,DIRECT,no-resolve',
      #   'GEOIP,LAN,DIRECT',
      #   'GEOIP,CN,DIRECT'
      # ].reverse.each { |r| Value['rules'].unshift(r) }

    
      #4. AdHoc RULES
      [
        'DOMAIN-SUFFIX,singaporeair.com,' + proxy_group_name
      ].reverse.each { |r| Value['rules'].unshift(r) }

      # Microsoft domains for all devices — routes to Microsoft proxy group if it exists.
      # Tiva's device overrides these via tiva_direct_domains (DIRECT wins due to higher priority).
      # Duplicates with subscription Microsoft rules are harmless — first match wins.
      ms_group = Value['proxy-groups'].find { |g| g['name'] == 'Microsoft' }
      if ms_group
        [
          'DOMAIN-SUFFIX,sharepoint.com,Microsoft',
          'DOMAIN-SUFFIX,onedrive.com,Microsoft',
          'DOMAIN-SUFFIX,outlook.com,Microsoft',
          'DOMAIN-SUFFIX,office.com,Microsoft',
          'DOMAIN-SUFFIX,office365.com,Microsoft',
          'DOMAIN-SUFFIX,office.net,Microsoft',
          'DOMAIN-SUFFIX,live.com,Microsoft',
          'DOMAIN-SUFFIX,windows.com,Microsoft',
          'DOMAIN-SUFFIX,windows.net,Microsoft',
          'DOMAIN-SUFFIX,microsoft.com,Microsoft',
          'DOMAIN-SUFFIX,cloud.microsoft,Microsoft',
          'DOMAIN-SUFFIX,microsoftonline.com,Microsoft',
          'DOMAIN-SUFFIX,teams.microsoft.com,Microsoft',
        ].reverse.each { |r| Value['rules'].unshift(r) }
      end
    
    
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
        'DOMAIN-KEYWORD,stan.aka,Aus 🇦🇺',
        'DOMAIN-SUFFIX,stan.sakamai.net,Aus 🇦🇺',
        'DOMAIN-SUFFIX,youboranqs01.com,Aus 🇦🇺',
        'DOMAIN-SUFFIX,nice264.com,Aus 🇦🇺',
        'DOMAIN-SUFFIX,akamaihd.net,Aus 🇦🇺',
        'GEOIP,AU,Aus 🇦🇺'
      ].reverse.each { |r| Value['rules'].unshift(r) }



      # 2. Azure CIDR
      Value['rules'].unshift('RULE-SET,Azure_US_West,Azure_US_West')
      Value['rules'].unshift('RULE-SET,Azure_US_East,Azure_US_East')
      Value['rules'].unshift('RULE-SET,Azure_West_Europe,Azure_West_Europe')

      # Microsoft Teams media IPs — IP-based UDP traffic (no hostname, domain rules never match).
      # Non-tiva devices: route via Microsoft proxy group if it exists.
      # Tiva's device: AND rules generated below from the same file, pointing to MicrosoftTiva.
      ms_group = Value['proxy-groups'].find { |g| g['name'] == 'Microsoft' }
      Value['rules'].unshift('RULE-SET,Microsoft_Teams,Microsoft,no-resolve') if ms_group

      # 1. Tiva's Microsoft - device-specific DIRECT routing
      #    Dynamically mirrors every rule in the subscription's Microsoft proxy
      #    group as a device-specific AND rule pointing to MicrosoftTiva.
      #    Must be above Azure CIDR rules — many Microsoft IPs overlap with them.
      tiva_ips = [
        '10.0.0.98', # laptop
        #'10.0.0.109', # iphone
        #'10.0.0.216', # ipad
        #'10.0.0.221', # xiaomi pro
      ]
      supported = %w[DOMAIN DOMAIN-SUFFIX DOMAIN-KEYWORD]

      tiva_rules = tiva_ips.flat_map do |ip|
        Value['rules']
          .select  { |r| r.end_with?(',Microsoft') }
          .map do |rule|
            parts      = rule.split(',')
            rule_type  = parts[0]
            rule_value = parts[1..-2].join(',')
            next unless supported.include?(rule_type)
            \"AND,((SRC-IP-CIDR,#{ip}/32),(#{rule_type},#{rule_value})),MicrosoftTiva\"
          end
          .compact
      end

      tiva_rules.reverse.each { |r| Value['rules'].unshift(r) }

      # Tiva's Teams media — read CIDRs from the downloaded rule provider file and generate
      # device-specific AND rules pointing to MicrosoftTiva.
      # Stays in sync with microsoft_teams.yaml automatically on each restart.
      teams_path = '/etc/openclash/rule_provider/microsoft_teams.yaml'
      if File.exist?(teams_path)
        teams_cidrs = YAML.load_file(teams_path)['payload'] || []
        tiva_ips.each do |ip|
          teams_cidrs
            .reject { |cidr| cidr.include?(':') }
            .reverse.each { |cidr| Value['rules'].unshift(\"AND,((SRC-IP-CIDR,#{ip}/32),(IP-CIDR,#{cidr})),MicrosoftTiva\") }
        end
      end

      # 0. Tiva's additional DIRECT rules — hardcoded domains that always bypass proxy
      #    for tiva's device regardless of what the subscription's Microsoft group contains.
      #
      #    Priority: tiva_direct_rules are prepended AFTER tiva_rules, so they sit higher
      #    in the final rule list and always win. Duplicates with tiva_rules or Value['rules']
      #    are harmless — Clash stops at the first match.
      #
      #    Microsoft domains are also injected into AdHoc rules (pointing to the Microsoft
      #    proxy group) for all other devices. Any overlap with subscription rules is fine.
      tiva_direct_domains = [
        # Banks
        ['DOMAIN-SUFFIX', 'eqi.com.br'],
        ['DOMAIN-SUFFIX', 'btgpactual.com'],
        # Suzano
        ['DOMAIN-SUFFIX', 'cloudpay.net'],
        ['DOMAIN-SUFFIX', 'suzano.com.br'],
        ['DOMAIN-SUFFIX', 'replicon.com'],
        ['DOMAIN-SUFFIX', 'service-now.com'],
        ['DOMAIN-SUFFIX', 'optionsreport.net'],
        ['DOMAIN-SUFFIX', 'concursolutions.com'],
        ['DOMAIN-SUFFIX', 'apptentive.com'],
        ['DOMAIN-SUFFIX', 'cloud.sap'],
      ]

      tiva_direct_rules = tiva_ips.flat_map do |ip|
        tiva_direct_domains.map do |rule_type, rule_value|
          \"AND,((SRC-IP-CIDR,#{ip}/32),(#{rule_type},#{rule_value})),DIRECT\"
        end
      end

      tiva_direct_rules.reverse.each { |r| Value['rules'].unshift(r) }
      
      

      

    end

    File.open('$CONFIG_FILE','w') {|f| YAML.dump(Value, f)}
    puts '${LOGTIME} Clash rules configured successfully'
  rescue Exception => e
    puts '${LOGTIME} Error: ' + e.message
  end
" 2>/dev/null >> $LOG_FILE

exit 0